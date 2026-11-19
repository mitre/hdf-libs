import Ajv, { type ValidateFunction, type ErrorObject } from 'ajv';
import addFormats from 'ajv-formats';
import Ajv2020 from 'ajv/dist/2020.js';

// Pinned HDF v2 (Heimdall/InSpec exec-json) schema — sourced from heimdall2
// inspecjs (see ../go/legacy/PROVENANCE.md). One copy, which Go embeds from its
// own package directory because go:embed cannot reach outside it.
import legacyV2Schema from '../go/legacy/exec-json.schema.json';

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
  hdfRequirementChangeEventSchema,
  commonSchema,
  eventsSchema,
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
  bomSchema,
} from '@mitre/hdf-schema';

/**
 * Validation error details
 */
export interface ValidationError {
  field: string;
  message: string;
  value?: unknown;
  /**
   * The JSON Schema keyword that failed ('type', 'required', 'format', ...).
   * Surfaced so a caller can act on the KIND of violation — the converters
   * reject a wrongly-typed field without rejecting a merely sparse document.
   */
  keyword?: string;
  /** For a failed `format`, which format was expected. */
  format?: string;
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
function createValidator(): Ajv2020 {
  const ajv = new Ajv2020({
    allErrors: true,
    verbose: true,
    strict: false,
    validateFormats: true,
    validateSchema: false // Skip meta-schema validation for performance
  });

  // Add format validators (date-time, uri, etc.)
  addFormats(ajv);
  // ajv-formats follows the RFC 3339 note allowing a space where the T belongs;
  // HDF's canonical timestamp does not, and the Go peer rejects it. Requiring the
  // separator keeps the shipped validators on one answer — both languages' verdicts
  // are pinned by ../testdata/shipped-format-cases.json.
  const registeredDateTime = ajv.formats['date-time'] as { validate: (v: string) => boolean };
  ajv.addFormat('date-time', {
    type: 'string',
    validate: (v: string) => /^\d{4}-\d{2}-\d{2}[Tt]/.test(v) && registeredDateTime.validate(v),
  });

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
  ajv.addSchema(bomSchema);          // referenced by Base_Component.boms[]
  ajv.addSchema(amendmentsSchema);   // before extensions (extensions $refs amendments Override_Type)
  ajv.addSchema(extensionsSchema);
  ajv.addSchema(systemSchema);
  ajv.addSchema(planSchema);
  ajv.addSchema(comparisonSchema);
  ajv.addSchema(eventsSchema);      // change-event envelope (referenced by hdf-requirement-change-event)
  ajv.addSchema(componentSchema);
  ajv.addSchema(dataFlowSchema);

  // Register top-level schemas so cross-schema $refs resolve.
  // The comparison primitive references hdf-results#/$defs/Evaluated_Requirement,
  // so hdf-results must be registered before compiling comparison.
  // Ajv compiles these schema objects lazily and caches the compiled validators.
  ajv.addSchema(hdfResultsSchema);
  ajv.addSchema(hdfBaselineSchema);
  ajv.addSchema(hdfComparisonSchema);
  ajv.addSchema(hdfSystemSchema);
  ajv.addSchema(hdfPlanSchema);
  ajv.addSchema(hdfAmendmentsSchema);
  ajv.addSchema(hdfRequirementChangeEventSchema);
  ajv.addSchema(hdfEvidencePackageSchema);

  return ajv;
}

// Singleton Ajv instance
const ajv = createValidator();

/**
 * Convert Ajv errors to ValidationError format
 */
function formatErrors(errors: ErrorObject[] | null | undefined): ValidationError[] {
  return errors?.map(formatError) ?? [];
}

function formatError(err: ErrorObject): ValidationError {
  let field = err.instancePath.replace(/^\//, '').replace(/\//g, '.');
  if (!field && err.schemaPath && err.keyword !== 'unevaluatedProperties') {
    const pathParts = err.schemaPath.split('/');
    field = pathParts[pathParts.length - 1] || '(root)';
  }
  const diagnostic = errorDiagnostic(err, field);
  return {
    field: diagnostic.field || '(root)',
    keyword: err.keyword,
    ...(err.keyword === 'format' && err.params && 'format' in err.params
      ? { format: String((err.params as { format: unknown }).format) }
      : {}),
    message: diagnostic.message,
    value: err.data,
  };
}

function errorDiagnostic(err: ErrorObject, field: string): { field: string; message: string } {
  const message = err.message || 'validation failed';
  if (!err.params) return { field, message };
  if ('missingProperty' in err.params) {
    return {
      field: field ? `${field}.${err.params.missingProperty}` : err.params.missingProperty,
      message: 'is required',
    };
  }
  if ('additionalProperty' in err.params) {
    const hint = err.keyword === 'additionalProperties'
      && /^\/(?:baselines\/\d+\/)?extensions$/.test(err.instancePath)
      ? '. Move producer-specific data under extensions.passthrough, namespaced by tool name.' : '';
    return {
      field: field ? `${field}.${err.params.additionalProperty}` : err.params.additionalProperty,
      message: `is not allowed${hint}`,
    };
  }
  if ('unevaluatedProperty' in err.params) {
    return {
      field: field ? `${field}.${err.params.unevaluatedProperty}` : err.params.unevaluatedProperty,
      message: 'is not allowed',
    };
  }
  return { field, message: 'limit' in err.params ? `${message} (limit: ${err.params.limit})` : message };
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
  return createResult(ajv.compile(hdfResultsSchema), data);
}

// Legacy HDF v2 (Heimdall/InSpec exec-json) uses its own Ajv instance: the pinned
// exec-json schema is self-contained and unrelated to the HDF v3 schemas, so it
// stays isolated from the shared HDF validator.
let legacyV2Validator: ValidateFunction | null = null;
function getLegacyV2Validator(): ValidateFunction {
  if (!legacyV2Validator) {
    const v2ajv = new Ajv({ allErrors: true, verbose: true, strict: false, validateSchema: false });
    addFormats(v2ajv);
    legacyV2Validator = v2ajv.compile(legacyV2Schema);
  }
  return legacyV2Validator;
}

/**
 * Validate a legacy HDF v2 document — the Heimdall/InSpec exec-json shape
 * (profiles[] + platform) SAF converters emit — against the pinned exec-json
 * schema, at the same Ajv rigor as the v3 validators.
 */
export function validateLegacyV2(data: unknown): ValidationResult {
  return createResult(getLegacyV2Validator(), data);
}

/**
 * Validate HDF Baseline document against schema
 */
export function validateBaseline(data: unknown): ValidationResult {
  return createResult(ajv.compile(hdfBaselineSchema), data);
}

/**
 * Validate HDF Comparison document against schema
 */
export function validateComparison(data: unknown): ValidationResult {
  return createResult(ajv.compile(hdfComparisonSchema), data);
}

/**
 * Validate an HDF Requirement Change Event (one continuous-monitoring wire event) against schema
 */
export function validateRequirementChangeEvent(data: unknown): ValidationResult {
  return createResult(ajv.compile(hdfRequirementChangeEventSchema), data);
}

/**
 * Validate HDF System document against schema
 */
export function validateSystem(data: unknown): ValidationResult {
  return createResult(ajv.compile(hdfSystemSchema), data);
}

/**
 * Validate HDF Plan document against schema
 */
export function validatePlan(data: unknown): ValidationResult {
  return createResult(ajv.compile(hdfPlanSchema), data);
}

/**
 * Validate HDF Amendments document against schema
 */
export function validateAmendments(data: unknown): ValidationResult {
  return createResult(ajv.compile(hdfAmendmentsSchema), data);
}

/**
 * Validate HDF Evidence Package document against schema
 */
export function validateEvidencePackage(data: unknown): ValidationResult {
  return createResult(ajv.compile(hdfEvidencePackageSchema), data);
}

const documentValidators: readonly {
  keys: readonly string[];
  validate: (data: unknown) => ValidationResult;
}[] = [
  { keys: ['baselines'], validate: validateResults },
  { keys: ['name', 'requirements'], validate: validateBaseline },
  { keys: ['name', 'components'], validate: validateSystem },
  { keys: ['name', 'assessments'], validate: validatePlan },
  { keys: ['name', 'overrides'], validate: validateAmendments },
  { keys: ['eventId', 'requirementId'], validate: validateRequirementChangeEvent },
  { keys: ['requirementDiffs'], validate: validateComparison },
  { keys: ['name', 'contents'], validate: validateEvidencePackage },
];

/**
 * Validate HDF document (auto-detect type based on structure)
 */
export function validate(data: unknown): ValidationResult {
  if (typeof data !== 'object' || data === null) return validateResults(data);
  const match = documentValidators.find(({ keys }) => keys.every(key => key in data));
  return (match?.validate ?? validateResults)(data);
}
