import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Creates and configures an Ajv instance with all primitive schemas loaded.
 * Use this for validating the new refactored schemas that use $ref.
 */
export function createAjvWithPrimitives(): Ajv {
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);

  const primitivesDir = path.join(__dirname, '../src/schemas/primitives');
  const primitiveFiles = [
    'common.schema.json',
    'platform.schema.json',
    'target.schema.json',
    'runner.schema.json',
    'statistics.schema.json',
    'result.schema.json',
    'extensions.schema.json',
  ];

  for (const file of primitiveFiles) {
    const schema = JSON.parse(fs.readFileSync(path.join(primitivesDir, file), 'utf-8'));
    ajv.addSchema(schema);
  }

  return ajv;
}

/**
 * Loads a schema file from the schemas directory.
 */
export function loadSchema(filename: string): object {
  const schemaPath = path.join(__dirname, '../src/schemas', filename);
  return JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
}

/**
 * Loads a test fixture file from the fixtures directory.
 */
export function loadFixture(filename: string): object {
  const fixturePath = path.join(__dirname, 'fixtures', filename);
  return JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
}

/**
 * Creates a minimal valid hdf-results document.
 * Use spread to override specific fields for test variations.
 */
export function createMinimalResultsDoc(overrides: object = {}): object {
  return {
    profiles: [],
    statistics: {},
    ...overrides,
  };
}

/**
 * Creates a minimal valid hdf-baseline document.
 * Use spread to override specific fields for test variations.
 */
export function createMinimalBaselineDoc(overrides: object = {}): object {
  return {
    name: 'test-baseline',
    supports: [],
    requirements: [],
    groups: [],
    checksum: { algorithm: 'sha256', value: 'abc123def456' },
    ...overrides,
  };
}

/**
 * Creates a minimal valid evaluated baseline for use in results documents.
 */
export function createMinimalEvaluatedBaseline(overrides: object = {}): object {
  return {
    name: 'test-baseline',
    checksum: { algorithm: 'sha256', value: 'abc123' },
    supports: [],
    attributes: [],
    groups: [],
    requirements: [],
    ...overrides,
  };
}

/**
 * Creates a minimal valid control/requirement for use in profiles.
 */
export function createMinimalControl(overrides: object = {}): object {
  return {
    id: 'SV-238196',
    impact: 0.7,
    tags: {},
    source_location: {},
    results: [],
    descriptions: [
      { label: 'default', data: 'Minimal test control description' }
    ],
    ...overrides,
  };
}

/**
 * Creates a minimal valid baseline requirement (no results).
 */
export function createMinimalBaselineControl(overrides: object = {}): object {
  return {
    id: 'SV-238196',
    impact: 0.7,
    tags: {},
    code: 'control "SV-238196" do\nend',
    descriptions: [
      { label: 'default', data: 'Minimal baseline control description' }
    ],
    ...overrides,
  };
}

/**
 * Creates a minimal valid result.
 */
export function createMinimalResult(overrides: object = {}): object {
  return {
    code_desc: 'Test description',
    start_time: '2025-11-25T12:00:00Z',
    ...overrides,
  };
}
