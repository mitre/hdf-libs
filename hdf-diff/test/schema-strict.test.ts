import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { diffHdf } from '../src/diff.js';

// The shipped validators do not enforce unevaluatedProperties, which is how an
// undeclared property on every comparison document went unnoticed. This guard
// runs real engine output through a 2020-12 engine that does.
const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = resolve(__dirname, 'fixtures');
const load = (name: string): unknown => JSON.parse(readFileSync(resolve(fixtures, name), 'utf-8'));
const bundled = JSON.parse(
  readFileSync(resolve(__dirname, '..', '..', 'hdf-validators', 'go', 'schemas', 'hdf-comparison.schema.json'), 'utf-8'),
) as Record<string, unknown>;

function strictValidator(schema: Record<string, unknown>) {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

describe('comparison documents under a 2020-12 engine that enforces unevaluatedProperties', () => {
  const validate = strictValidator(bundled);

  it('accepts diffHdf output', () => {
    const comparison = diffHdf(load('scan-before.json'), load('scan-after.json'));
    expect(validate(comparison), JSON.stringify(validate.errors?.slice(0, 3))).toBe(true);
  });

  it('accepts the MCP comparison fixture hdf diff produced', () => {
    const doc = JSON.parse(
      readFileSync(resolve(__dirname, '..', '..', 'hdf-cli', 'internal', 'mcp', 'tools', 'testdata', 'comparison.json'), 'utf-8'),
    );
    expect(validate(doc), JSON.stringify(validate.errors?.slice(0, 3))).toBe(true);
  });

  it('is load-bearing: the same output fails once baseline is undeclared again', () => {
    // The bundle keys its definitions by primitive URL, so locate the one by shape.
    const mutant = structuredClone(bundled);
    const requirementDiff = Object.values(mutant.$defs as Record<string, { $defs: Record<string, unknown> }>)
      .flatMap((primitive) => Object.values(primitive.$defs ?? {}))
      .find((def) => 'matchStrategy' in ((def as { properties?: Record<string, unknown> }).properties ?? {})) as {
      properties: Record<string, unknown>;
    };
    expect(requirementDiff.properties).toHaveProperty('baseline');
    delete requirementDiff.properties['baseline'];
    const comparison = diffHdf(load('scan-before.json'), load('scan-after.json'));
    expect(strictValidator(mutant)(comparison)).toBe(false);
  });
});
