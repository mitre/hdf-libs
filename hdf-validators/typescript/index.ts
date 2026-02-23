import Ajv, { type ValidateFunction, type ErrorObject } from 'ajv';
import addFormats from 'ajv-formats';

// Import all schemas (bare JSON imports — bundled by Vite via noExternal config)
import hdfResultsSchema from '@mitre/hdf-schema/schemas/hdf-results.schema.json';
import hdfBaselineSchema from '@mitre/hdf-schema/schemas/hdf-baseline.schema.json';
import commonSchema from '@mitre/hdf-schema/schemas/primitives/common.schema.json';
import extensionsSchema from '@mitre/hdf-schema/schemas/primitives/extensions.schema.json';
import platformSchema from '@mitre/hdf-schema/schemas/primitives/platform.schema.json';
import resultSchema from '@mitre/hdf-schema/schemas/primitives/result.schema.json';
import runnerSchema from '@mitre/hdf-schema/schemas/primitives/runner.schema.json';
import statisticsSchema from '@mitre/hdf-schema/schemas/primitives/statistics.schema.json';
import targetSchema from '@mitre/hdf-schema/schemas/primitives/target.schema.json';

/**
 * Validation error details
 */
export interface ValidationError {
  field: string;
  message: string;
  value?: unknown;
}

/**
 * Result of schema validation
 */
export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  getErrorMessage(): string;
}

/**
 * Create and configure Ajv instance with all HDF schemas
 */
function createValidator(): Ajv {
  const ajv = new Ajv({
    allErrors: true,
    verbose: true,
    strict: false,
    validateFormats: true,
    validateSchema: false // Skip meta-schema validation for performance
  });

  // Add format validators (date-time, uri, etc.)
  addFormats(ajv);

  // Add all primitive schemas so they can be referenced
  ajv.addSchema(commonSchema);
  ajv.addSchema(extensionsSchema);
  ajv.addSchema(platformSchema);
  ajv.addSchema(resultSchema);
  ajv.addSchema(runnerSchema);
  ajv.addSchema(statisticsSchema);
  ajv.addSchema(targetSchema);

  return ajv;
}

// Singleton Ajv instance
const ajv = createValidator();

// Compile schemas once
let resultsValidator: ValidateFunction | null = null;
let baselineValidator: ValidateFunction | null = null;

/**
 * Get or compile the HDF Results validator
 */
function getResultsValidator(): ValidateFunction {
  if (!resultsValidator) {
    resultsValidator = ajv.compile(hdfResultsSchema);
  }
  return resultsValidator;
}

/**
 * Get or compile the HDF Baseline validator
 */
function getBaselineValidator(): ValidateFunction {
  if (!baselineValidator) {
    baselineValidator = ajv.compile(hdfBaselineSchema);
  }
  return baselineValidator;
}

/**
 * Convert Ajv errors to ValidationError format
 */
function formatErrors(errors: ErrorObject[] | null | undefined): ValidationError[] {
  if (!errors || errors.length === 0) {
    return [];
  }

  return errors.map(err => {
    // Clean up field path (remove leading slash, use dot notation)
    let field = err.instancePath
      .replace(/^\//, '')
      .replace(/\//g, '.');

    // If field is empty, use the data path from the error
    if (!field && err.schemaPath) {
      const pathParts = err.schemaPath.split('/');
      field = pathParts[pathParts.length - 1] || '(root)';
    }

    // Build message
    let message = err.message || 'validation failed';
    if (err.params) {
      // Add parameter info for more context
      if ('missingProperty' in err.params) {
        field = field ? `${field}.${err.params.missingProperty}` : err.params.missingProperty;
        message = 'is required';
      } else if ('additionalProperty' in err.params) {
        field = field ? `${field}.${err.params.additionalProperty}` : err.params.additionalProperty;
        message = 'is not allowed';
      } else if ('limit' in err.params) {
        message = `${message} (limit: ${err.params.limit})`;
      }
    }

    return {
      field: field || '(root)',
      message,
      value: err.data
    };
  });
}

/**
 * Create ValidationResult from validator output
 */
function createResult(validator: ValidateFunction, data: unknown): ValidationResult {
  const valid = validator(data);

  const errors = formatErrors(validator.errors);

  return {
    valid: valid === true,
    errors,
    getErrorMessage(): string {
      if (this.valid) {
        return '';
      }
      return this.errors
        .map(e => {
          if (e.field === '(root)') {
            return e.message;
          }
          return `${e.field}: ${e.message}`;
        })
        .join('; ');
    }
  };
}

/**
 * Validate HDF Results document against schema
 * @param data - HDF Results document (JavaScript object)
 * @returns Validation result with errors if invalid
 */
export function validateResults(data: unknown): ValidationResult {
  const validator = getResultsValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF Baseline document against schema
 * @param data - HDF Baseline document (JavaScript object)
 * @returns Validation result with errors if invalid
 */
export function validateBaseline(data: unknown): ValidationResult {
  const validator = getBaselineValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF document (auto-detect type based on structure)
 * @param data - HDF document (JavaScript object)
 * @returns Validation result with errors if invalid
 */
export function validate(data: unknown): ValidationResult {
  // Try to auto-detect type based on structure
  if (typeof data === 'object' && data !== null) {
    const obj = data as Record<string, unknown>;

    // HDF Results has 'baselines' array at root
    if ('baselines' in obj) {
      return validateResults(data);
    }

    // HDF Baseline has 'name' and 'requirements' at root
    if ('name' in obj && 'requirements' in obj) {
      return validateBaseline(data);
    }
  }

  // Cannot determine type, try results first
  const resultsResult = validateResults(data);
  if (resultsResult.valid) {
    return resultsResult;
  }

  // Try baseline
  const baselineResult = validateBaseline(data);
  if (baselineResult.valid) {
    return baselineResult;
  }

  // Return results validation errors (most common case)
  return resultsResult;
}
