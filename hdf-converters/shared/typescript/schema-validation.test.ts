import { readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  loadSchemaValidator,
  loadSchemaValidatorWithResources,
  assertSchemaValid,
} from './schema-validation.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const convDir = join(__dirname, '..', '..', 'converters');
// OpenVEX 0.2.0 schema (draft 2020-12) + a known-valid document (a converter golden).
const validate = loadSchemaValidator(
  join(convDir, 'openvex-to-hdf', 'fixtures', 'openvex_json_schema.json'),
);
const validDoc = JSON.parse(
  readFileSync(
    join(convDir, 'hdf-to-openvex', 'fixtures', 'expected', 'multi-status-amendments.openvex.json'),
    'utf-8',
  ),
) as unknown;

describe('shared schema-validation harness', () => {
  it('accepts a valid document', () => {
    expect(() => assertSchemaValid(validate, 'valid', validDoc)).not.toThrow();
  });

  it('reports schema errors for an invalid document', () => {
    expect(() => assertSchemaValid(validate, 'bad', {})).toThrow(/does not satisfy the schema/);
  });

  it('defaults to draft-07 for a schema without $schema', () => {
    const path = join(tmpdir(), 'hdf-schema-validation-noschema.json');
    writeFileSync(path, JSON.stringify({ type: 'object', required: ['x'], properties: { x: { type: 'string' } } }));
    try {
      const v = loadSchemaValidator(path);
      expect(() => assertSchemaValid(v, 'ok', { x: 'y' })).not.toThrow();
      expect(() => assertSchemaValid(v, 'missing', {})).toThrow(/does not satisfy the schema/);
    } finally {
      rmSync(path, { force: true });
    }
  });
});

// Every vendored schema compiles here too. The Go peer runs the same sweep with
// gojsonschema; ajv and gojsonschema do not accept the same documents, so a
// schema loading in one is no evidence about the other.
//
// Provenance (hash + source URL) is asserted in the Go peer ONLY: hashing a file
// and re-fetching a URL are language-independent, so a second copy adds no
// signal. Compilation is not language-independent, which is why it lives in both.
describe('every vendored schema', () => {
  // Found by content, not by directory name -- a schema parked in fixtures/ is
  // still a schema, and scoping this to schemas/ would under-report while still
  // reporting green. One location IS excluded, matching the Go peer:
  // fixtures/expected/, which holds this repo's own converter output rather than
  // anything vendored. A schema placed there would not be covered.
  const all: { label: string; path: string; draft04: boolean; refs: string }[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name !== 'node_modules' && e.name !== 'expected') walk(full);
      } else if (e.name.endsWith('.json') && e.name !== 'provenance.json') {
        let raw: string;
        try {
          raw = readFileSync(full, 'utf-8');
        } catch {
          continue;
        }
        let parsed: { $schema?: string } | undefined;
        try {
          parsed = JSON.parse(raw) as { $schema?: string };
        } catch {
          continue; // deliberately malformed fixtures exist to exercise error paths
        }
        if (!parsed || typeof parsed !== 'object' || !('$schema' in parsed)) continue;
        all.push({
          label: `${basename(dirname(dirname(full)))}/${e.name}`,
          path: full,
          draft04: (parsed.$schema ?? '').includes('draft-04'),
          refs: raw,
        });
      }
    }
  };
  walk(convDir);

  // ajv 8 dropped draft-04. A draft-04 file cannot compile here, and neither can
  // one that $refs it, because the companion cannot be registered either. That is
  // an ajv limitation rather than a defect in the vendored file, and the Go peer
  // (gojsonschema) does compile them, so coverage is not lost -- only narrowed.
  const draft04Names = all.filter((s) => s.draft04).map((s) => basename(s.path));
  const blocked = (s: { draft04: boolean; refs: string }): boolean =>
    s.draft04 || draft04Names.some((n) => s.refs.includes(n));

  const compilable = all.filter((s) => !blocked(s));
  const skipped = all.filter(blocked).map((s) => s.label).sort();

  it('finds enough schemas for this to be meaningful', () => {
    expect(compilable.length).toBeGreaterThan(3);
  });

  // Pinned so the exclusion cannot quietly widen into "ajv checks nothing".
  it('excludes only the known draft-04 family', () => {
    expect(skipped).toEqual([
      'csaf-vex-to-hdf/csaf_json_schema.json',
      'csaf-vex-to-hdf/cvss-v2.0.json',
      'csaf-vex-to-hdf/cvss-v3.0.json',
    ]);
  });

  // Some vendored schemas $ref a sibling by URL (CycloneDX -> SPDX/JSF), so
  // compiling one in isolation fails. Every other .json in the same directory is
  // registered under its own $id, which is exactly the URL such a $ref uses.
  const companionsFor = (path: string): Record<string, string> => {
    const dir = dirname(path);
    const map: Record<string, string> = {};
    for (const f of readdirSync(dir).filter((n) => n.endsWith('.json') && n !== 'provenance.json')) {
      const full = join(dir, f);
      if (full === path) continue;
      try {
        const id = (JSON.parse(readFileSync(full, 'utf-8')) as { $id?: string }).$id;
        if (id) map[id] = full;
      } catch {
        /* not a schema; skip */
      }
    }
    return map;
  };

  it.each(compilable.map((s) => [s.label, s.path] as const))('compiles %s', (_label, path) => {
    expect(() => loadSchemaValidatorWithResources(path, companionsFor(path))).not.toThrow();
  });
});
