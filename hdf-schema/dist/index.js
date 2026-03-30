/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions
 */

// Re-export all values from hdf-results (enums like ResultStatus, HashAlgorithm, Severity)
export * from './ts/hdf-results.js';

// Re-export comparison-specific enums (runtime values not in hdf-results)
export {
  AnnotationCategory, CapturedByType, ChangeReason, ComparisonMode,
  ConflictResolution, FormatVersion, MatchStrategy, Op, OriginalFormat,
  RequirementState, SourceRole, State, TypeEnum,
} from './ts/hdf-comparison.js';

// Re-export system enums (runtime values)
export {
  AuthorizationStatus, BoundaryDescription, CategorizationLevel, Designation, Direction,
} from './ts/hdf-system.js';

// Re-export plan enums (runtime values)
export {
  PlanType,
} from './ts/hdf-plan.js';

// Re-export amendments enums (runtime values)
export {
  OverrideType,
} from './ts/hdf-amendments.js';

// Re-export evidence-package enums (runtime values)
export {
  ContentType,
} from './ts/hdf-evidence-package.js';

// Re-export helper functions
export * from './helpers.js';
