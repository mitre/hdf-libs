/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions
 */

// Re-export all values from hdf-results (enums like ResultStatus, HashAlgorithm, Severity)
export * from './ts/hdf-results.js';

// Re-export comparison-specific enums (runtime values not in hdf-results)
export {
  AnnotationCategory, BaselineDiffState, ChangeReason, ComparisonMode,
  ConflictResolution, FormatVersion, MatchStrategy, Op, OriginalFormat,
  PackageDiffState, RequirementState, SourceRole, Type,
} from './ts/hdf-comparison.js';

// Re-export system enums (runtime values)
export {
  AuthorizationStatus, BoundaryDescription, CategorizationLevel, Designation, Direction,
} from './ts/hdf-system.js';

// Re-export plan enums (runtime values)
export {
  PlanType,
} from './ts/hdf-plan.js';

// No amendments enum re-export — OverrideType already from hdf-results via export *.

// Re-export evidence-package enums (runtime values)
export {
  ContentType,
} from './ts/hdf-evidence-package.js';

// Re-export helper functions
export * from './helpers.js';
