import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'vitest';
import { loadSchemaValidator, assertSchemaValid } from '../../../shared/typescript/schema-validation.js';
import { convertHdfToOpenVex } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// OpenVEX v0.2.0 schema (draft 2020-12). Vendored under openvex-to-hdf/fixtures.
const validate = loadSchemaValidator(
  join(__dirname, '..', '..', 'openvex-to-hdf', 'fixtures', 'openvex_json_schema.json'),
);
const loadInput = (name: string): string =>
  readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');

describe('hdf-to-openvex output validates against OpenVEX v0.2.0 schema', () => {
  it.each(['multi-status-amendments.json', 'spring-boot-log4j-amendments.json'])('%s', async (name) => {
    const out = JSON.parse(await convertHdfToOpenVex(loadInput(name), '1.0.0')) as unknown;
    assertSchemaValid(validate, name, out);
  });
});
