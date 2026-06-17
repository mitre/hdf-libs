import Ajv, { type ValidateFunction, type ErrorObject } from 'ajv';
import addFormats from 'ajv-formats';

// Named JS-object schema imports — the schemas are inlined into
// @mitre/hdf-schema's dist/index.js at build time, so downstream consumers
// never see raw JSON imports. Works uniformly in raw Node ESM, Vite/Nuxt,
// webpack, esbuild — no consumer-side noExternal configuration required.
import {
  hdfResultsSchema,
  hdfBaselineSchema,
  hdfComparisonSchema,
  hdfSystemSchema,
  hdfPlanSchema,
  hdfAmendmentsSchema,
  hdfEvidencePackageSchema,
  commonSchema,
  extensionsSchema,
  platformSchema,
  resultSchema,
  runnerSchema,
  statisticsSchema,
  targetSchema,
  parameterSchema,
  systemSchema,
  planSchema,
  amendmentsSchema,
  comparisonSchema,
  componentSchema,
  dataFlowSchema,
  cvssSchema,
  epssSchema,
  kevSchema,
  affectedPackageSchema,
} from '@mitre/hdf-schema';

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
  ajv.addSchema(cvssSchema);         // CVE-ecosystem primitives: referenced by Evaluated_Requirement + overrides
  ajv.addSchema(epssSchema);
  ajv.addSchema(kevSchema);
  ajv.addSchema(affectedPackageSchema);
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

    // HDF Comparison has 'requirementDiffs' at root (unique discriminator)
    if ('requirementDiffs' in obj) {
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
