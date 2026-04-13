import Ajv2020 from 'ajv/dist/2020.js';
import type { ValidateFunction } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Result of validating a document against the hdf-comparison schema.
 */
export interface ValidationResult {
  /** Whether the document conforms to the schema */
  valid: boolean;
  /** Human-readable error messages (only present when valid is false) */
  errors?: string[];
}

/**
 * Resolve the path to the hdf-schema package's schemas directory.
 *
 * In the monorepo layout, hdf-schema is a sibling package at `../hdf-schema`.
 * The schemas are in `src/schemas/` within that package.
 */
function schemasDir(): string {
  // From src/validate.ts (or dist/validate.js), go up to hdf-diff root, then to sibling
  return resolve(__dirname, '..', '..', 'hdf-schema', 'src', 'schemas');
}

/**
 * Load a JSON schema file from the hdf-schema package.
 */
function loadSchema(relativePath: string): Record<string, unknown> {
  const fullPath = resolve(schemasDir(), relativePath);
  return JSON.parse(readFileSync(fullPath, 'utf-8')) as Record<string, unknown>;
}

/** Cached compiled validator function */
let cachedValidator: ValidateFunction | null = null;

/**
 * Build and cache an Ajv 2020-12 validator for the hdf-comparison schema.
 *
 * Loads schemas in dependency order and reads each schema's $id at runtime
 * so that version changes in the schema files propagate automatically
 * without updating constants in this code.
 */
function getValidator(): ValidateFunction {
  if (cachedValidator) return cachedValidator;

  const ajv = new Ajv2020({
    strict: false,
    allErrors: true,
    validateFormats: true,
  });
  addFormats(ajv);

  // Load all primitive schemas first (order matters for $ref resolution).
  // Ajv registers each schema by its $id automatically.
  const primitiveFiles = [
    'primitives/common.schema.json',
    'primitives/platform.schema.json',
    'primitives/target.schema.json',
    'primitives/runner.schema.json',
    'primitives/statistics.schema.json',
    'primitives/result.schema.json',
    'primitives/amendments.schema.json',
    'primitives/extensions.schema.json',
    'primitives/parameter.schema.json',
    'primitives/component.schema.json',
    'primitives/data-flow.schema.json',
    'primitives/system.schema.json',
    'primitives/comparison.schema.json',
  ];

  for (const file of primitiveFiles) {
    ajv.addSchema(loadSchema(file));
  }

  // Load hdf-results (defines Evaluated_Requirement referenced by comparison)
  ajv.addSchema(loadSchema('hdf-results.schema.json'));

  // Load hdf-comparison and read its $id to compile the validator.
  // Reading $id from the schema file means version bumps propagate
  // without changing this code.
  const comparisonSchema = loadSchema('hdf-comparison.schema.json');
  ajv.addSchema(comparisonSchema);
  const comparisonId = comparisonSchema.$id as string;

  cachedValidator = ajv.getSchema(comparisonId)!;
  return cachedValidator;
}

/**
 * Format Ajv validation errors into human-readable strings.
 */
function formatErrors(validate: ValidateFunction): string[] {
  /* c8 ignore next -- Ajv always populates errors array when validation fails */
  return (validate.errors ?? []).map((err) => {
    const path = err.instancePath || '/';
    /* c8 ignore next -- Ajv always populates err.message */
    const msg = err.message ?? 'unknown error';
    // Ajv always populates err.params on validation errors.
    // The else branch exists for defensive typing since params is typed as optional.
    /* c8 ignore start */
    return err.params
      ? `${path}: ${msg} (${JSON.stringify(err.params)})`
      : `${path}: ${msg}`;
    /* c8 ignore stop */
  });
}

/**
 * Validate a document against the hdf-comparison schema.
 *
 * Loads and compiles all required schemas from the sibling hdf-schema package.
 * The compiled validator is cached for performance on subsequent calls.
 *
 * @param doc - The document to validate (typically the output of `diffHdf()`)
 * @returns Validation result with `valid` boolean and optional `errors` array
 */
export function validateComparison(doc: unknown): ValidationResult {
  const validate = getValidator();

  if (validate(doc)) {
    return { valid: true };
  }

  return { valid: false, errors: formatErrors(validate) };
}
