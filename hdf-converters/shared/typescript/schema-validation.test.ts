import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { loadSchemaValidator, assertSchemaValid } from './schema-validation.js';

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
