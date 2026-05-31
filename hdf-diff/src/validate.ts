import type { ValidationError } from '@mitre/hdf-validators';
import { validateComparison as validatorsValidateComparison } from '@mitre/hdf-validators';

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
 * Validate a document against the hdf-comparison schema.
 *
 * Delegates to @mitre/hdf-validators which loads schemas from embedded
 * bundled JSON (no filesystem access, no hardcoded version URLs).
 *
 * @param doc - The document to validate (typically the output of `diffHdf()`)
 * @returns Validation result with `valid` boolean and optional `errors` array
 */
export function validateComparison(doc: unknown): ValidationResult {
  const result = validatorsValidateComparison(doc);

  if (result.valid) {
    return { valid: true };
  }

  const errors = result.errors.map((e: ValidationError) =>
    e.field === '(root)' ? e.message : `${e.field}: ${e.message}`
  );
  return { valid: false, errors };
}
