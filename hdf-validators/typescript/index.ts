import Ajv, { type ValidateFunction, type ErrorObject } from 'ajv';
import addFormats from 'ajv-formats';

// Import all schemas (bare JSON imports — bundled by Vite via noExternal config)
import hdfResultsSchema from '@mitre/hdf-schema/schemas/hdf-results.schema.json';
import hdfBaselineSchema from '@mitre/hdf-schema/schemas/hdf-baseline.schema.json';
import hdfComparisonSchema from '@mitre/hdf-schema/schemas/hdf-comparison.schema.json';
import hdfSystemSchema from '@mitre/hdf-schema/schemas/hdf-system.schema.json';
import hdfPlanSchema from '@mitre/hdf-schema/schemas/hdf-plan.schema.json';
import hdfAmendmentsSchema from '@mitre/hdf-schema/schemas/hdf-amendments.schema.json';
import hdfEvidencePackageSchema from '@mitre/hdf-schema/schemas/hdf-evidence-package.schema.json';
import commonSchema from '@mitre/hdf-schema/schemas/primitives/common.schema.json';
import extensionsSchema from '@mitre/hdf-schema/schemas/primitives/extensions.schema.json';
import platformSchema from '@mitre/hdf-schema/schemas/primitives/platform.schema.json';
import resultSchema from '@mitre/hdf-schema/schemas/primitives/result.schema.json';
import runnerSchema from '@mitre/hdf-schema/schemas/primitives/runner.schema.json';
import statisticsSchema from '@mitre/hdf-schema/schemas/primitives/statistics.schema.json';
import targetSchema from '@mitre/hdf-schema/schemas/primitives/target.schema.json';
import parameterSchema from '@mitre/hdf-schema/schemas/primitives/parameter.schema.json';
import systemSchema from '@mitre/hdf-schema/schemas/primitives/system.schema.json';
import planSchema from '@mitre/hdf-schema/schemas/primitives/plan.schema.json';
import amendmentsSchema from '@mitre/hdf-schema/schemas/primitives/amendments.schema.json';
import comparisonSchema from '@mitre/hdf-schema/schemas/primitives/comparison.schema.json';
import componentSchema from '@mitre/hdf-schema/schemas/primitives/component.schema.json';
import dataFlowSchema from '@mitre/hdf-schema/schemas/primitives/data-flow.schema.json';

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

  // Add all primitive schemas so they can be referenced via $ref
  ajv.addSchema(commonSchema);
  ajv.addSchema(platformSchema);
  ajv.addSchema(resultSchema);
  ajv.addSchema(runnerSchema);
  ajv.addSchema(statisticsSchema);
  ajv.addSchema(targetSchema);
  ajv.addSchema(parameterSchema);
  ajv.addSchema(amendmentsSchema);   // before extensions (extensions $refs amendments Override_Type)
  ajv.addSchema(extensionsSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(planSchema);
  ajv.addSchema(comparisonSchema);
  ajv.addSchema(componentSchema);
  ajv.addSchema(dataFlowSchema);

  // Register top-level schemas so cross-schema $refs resolve.
  // The comparison primitive references hdf-results#/$defs/Evaluated_Requirement,
  // so hdf-results must be registered before compiling comparison.
  // Schemas are compiled lazily (in getXxxValidator) for performance.
  ajv.addSchema(hdfResultsSchema);
  ajv.addSchema(hdfBaselineSchema);
  ajv.addSchema(hdfComparisonSchema);
  ajv.addSchema(hdfSystemSchema);
  ajv.addSchema(hdfPlanSchema);
  ajv.addSchema(hdfAmendmentsSchema);
  ajv.addSchema(hdfEvidencePackageSchema);

  return ajv;
}

// Singleton Ajv instance
const ajv = createValidator();

// Compile schemas once (lazy initialization)
let resultsValidator: ValidateFunction | null = null;
let baselineValidator: ValidateFunction | null = null;
let comparisonValidator: ValidateFunction | null = null;
let systemValidator: ValidateFunction | null = null;
let planValidator: ValidateFunction | null = null;
let amendmentsValidator: ValidateFunction | null = null;
let evidencePackageValidator: ValidateFunction | null = null;

function getResultsValidator(): ValidateFunction {
  if (!resultsValidator) {
    resultsValidator = ajv.compile(hdfResultsSchema);
  }
  return resultsValidator;
}

function getBaselineValidator(): ValidateFunction {
  if (!baselineValidator) {
    baselineValidator = ajv.compile(hdfBaselineSchema);
  }
  return baselineValidator;
}

function getComparisonValidator(): ValidateFunction {
  if (!comparisonValidator) {
    comparisonValidator = ajv.compile(hdfComparisonSchema);
  }
  return comparisonValidator;
}

function getSystemValidator(): ValidateFunction {
  if (!systemValidator) {
    systemValidator = ajv.compile(hdfSystemSchema);
  }
  return systemValidator;
}

function getPlanValidator(): ValidateFunction {
  if (!planValidator) {
    planValidator = ajv.compile(hdfPlanSchema);
  }
  return planValidator;
}

function getAmendmentsValidator(): ValidateFunction {
  if (!amendmentsValidator) {
    amendmentsValidator = ajv.compile(hdfAmendmentsSchema);
  }
  return amendmentsValidator;
}

function getEvidencePackageValidator(): ValidateFunction {
  if (!evidencePackageValidator) {
    evidencePackageValidator = ajv.compile(hdfEvidencePackageSchema);
  }
  return evidencePackageValidator;
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
 */
export function validateResults(data: unknown): ValidationResult {
  const validator = getResultsValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF Baseline document against schema
 */
export function validateBaseline(data: unknown): ValidationResult {
  const validator = getBaselineValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF Comparison document against schema
 */
export function validateComparison(data: unknown): ValidationResult {
  const validator = getComparisonValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF System document against schema
 */
export function validateSystem(data: unknown): ValidationResult {
  const validator = getSystemValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF Plan document against schema
 */
export function validatePlan(data: unknown): ValidationResult {
  const validator = getPlanValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF Amendments document against schema
 */
export function validateAmendments(data: unknown): ValidationResult {
  const validator = getAmendmentsValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF Evidence Package document against schema
 */
export function validateEvidencePackage(data: unknown): ValidationResult {
  const validator = getEvidencePackageValidator();
  return createResult(validator, data);
}

/**
 * Validate HDF document (auto-detect type based on structure)
 */
export function validate(data: unknown): ValidationResult {
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

    // HDF System has 'name' and 'components' at root
    if ('name' in obj && 'components' in obj) {
      return validateSystem(data);
    }

    // HDF Plan has 'name' and 'assessments' at root
    if ('name' in obj && 'assessments' in obj) {
      return validatePlan(data);
    }

    // HDF Amendments has 'name' and 'overrides' at root
    if ('name' in obj && 'overrides' in obj) {
      return validateAmendments(data);
    }

    // HDF Comparison has 'mode' and 'sources' at root
    if ('mode' in obj && 'sources' in obj) {
      return validateComparison(data);
    }

    // HDF Evidence Package has 'name' and 'contents' at root
    if ('name' in obj && 'contents' in obj) {
      return validateEvidencePackage(data);
    }
  }

  // Cannot determine type, try results first (most common)
  const resultsResult = validateResults(data);
  if (resultsResult.valid) {
    return resultsResult;
  }

  const baselineResult = validateBaseline(data);
  if (baselineResult.valid) {
    return baselineResult;
  }

  return resultsResult;
}
