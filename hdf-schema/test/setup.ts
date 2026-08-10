import Ajv2020 from 'ajv/dist/2020.js';
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
export function createAjvWithPrimitives(): Ajv2020 {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  const primitivesDir = path.join(__dirname, '../src/schemas/primitives');
  const primitiveFiles = [
    'common.schema.json',
    'platform.schema.json',
    'target.schema.json',
    'runner.schema.json',
    'statistics.schema.json',
    'result.schema.json',
    'cvss.schema.json',         // before amendments + extensions (both $ref the Cvss type)
    'epss.schema.json',
    'kev.schema.json',
    'affected-package.schema.json',
    'amendments.schema.json',   // before extensions (extensions.$ref → amendments Override_Type)
    'extensions.schema.json',
    'parameter.schema.json',
    'comparison.schema.json',
    'events.schema.json',       // after common (envelope $refs the Checksum type)
    'system.schema.json',
    'bom.schema.json',          // before component + hdf-system (both $ref the Bom type)
    'component.schema.json',
    'data-flow.schema.json',
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
    baselines: [],
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
    requirements: [
      {
        id: 'SV-238196',
        impact: 0.7,
        tags: {},
        code: 'control "SV-238196" do\nend',
        descriptions: [
          { label: 'default', data: 'Minimal baseline requirement description' }
        ],
      }
    ],
    integrity: { algorithm: 'sha256', checksum: 'abc123def456' },
    ...overrides,
  };
}

/**
 * Creates a minimal valid evaluated baseline for use in results documents.
 */
export function createMinimalEvaluatedBaseline(overrides: object = {}): object {
  return {
    name: 'test-baseline',
    integrity: { algorithm: 'sha256', checksum: 'abc123' },
    requirements: [
      {
        id: 'SV-238196',
        impact: 0.7,
        tags: {},
        sourceLocation: {},
        results: [
          {
            status: 'passed',
            codeDesc: 'Test description',
            startTime: '2025-11-25T12:00:00Z',
          }
        ],
        descriptions: [
          { label: 'default', data: 'Minimal test requirement description' }
        ],
      }
    ],
    ...overrides,
  };
}

/**
 * Creates a minimal valid requirement for use in evaluated baselines (with results).
 */
export function createMinimalRequirement(overrides: object = {}): object {
  return {
    id: 'SV-238196',
    impact: 0.7,
    tags: {},
    sourceLocation: {},
    results: [
      {
        status: 'passed',
        codeDesc: 'Test description',
        startTime: '2025-11-25T12:00:00Z',
      }
    ],
    descriptions: [
      { label: 'default', data: 'Minimal test requirement description' }
    ],
    ...overrides,
  };
}

/**
 * Creates a minimal valid baseline requirement (no results).
 */
export function createMinimalBaselineRequirement(overrides: object = {}): object {
  return {
    id: 'SV-238196',
    impact: 0.7,
    tags: {},
    code: 'control "SV-238196" do\nend',
    descriptions: [
      { label: 'default', data: 'Minimal baseline requirement description' }
    ],
    ...overrides,
  };
}

/**
 * Creates a minimal valid result.
 */
export function createMinimalResult(overrides: object = {}): object {
  return {
    status: 'passed',
    codeDesc: 'Test description',
    startTime: '2025-11-25T12:00:00Z',
    ...overrides,
  };
}

/**
 * Creates a minimal valid hdf-comparison document.
 * Use spread to override specific fields for test variations.
 */
export function createMinimalComparisonDoc(overrides: object = {}): object {
  return {
    formatVersion: '1.0.0',
    comparisonMode: 'temporal',
    sources: [
      { role: 'old', label: 'Before scan' },
      { role: 'new', label: 'After scan' },
    ],
    summary: {
      total: 0,
      matchedCount: 0,
      unmatchedOldCount: 0,
      unmatchedNewCount: 0,
    },
    requirementDiffs: [],
    ...overrides,
  };
}
