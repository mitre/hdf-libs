import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'vitest';
import { loadSchemaValidatorWithResources, assertSchemaValid } from '../../../shared/typescript/schema-validation.js';
import { convertHdfToCyclonedxVex } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const schemas = join(__dirname, '..', 'schemas');
const validate = loadSchemaValidatorWithResources(join(schemas, 'bom-1.4.schema.json'), {
  'http://cyclonedx.org/schema/spdx.schema.json': join(schemas, 'spdx.schema.json'),
  'http://cyclonedx.org/schema/jsf-0.82.schema.json': join(schemas, 'jsf-0.82.schema.json'),
});
const loadInput = (name: string): string =>
  readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');

describe('hdf-to-cyclonedx-vex output validates against CycloneDX v1.4 schema', () => {
  it.each(['case1-fixed-amendments.json', 'case1-not_affected-amendments.json'])('%s', async (name) => {
    const out = JSON.parse(await convertHdfToCyclonedxVex(loadInput(name), '1.0.0')) as unknown;
    assertSchemaValid(validate, name, out);
  });
});
