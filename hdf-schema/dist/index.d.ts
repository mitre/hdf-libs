/**
 * Main entry point for @mitre/hdf-schema
 * Re-exports all types from generated TypeScript definitions, plus the
 * 21 source schemas as named JS-object exports.
 */

// Inlined source schemas (with $refs intact — consumers register them
// individually with their JSON Schema validator to resolve cross-refs).
export declare const hdfAmendmentsSchema: Readonly<Record<string, unknown>>;
export declare const hdfBaselineSchema: Readonly<Record<string, unknown>>;
export declare const hdfComparisonSchema: Readonly<Record<string, unknown>>;
export declare const hdfEvidencePackageSchema: Readonly<Record<string, unknown>>;
export declare const hdfPlanSchema: Readonly<Record<string, unknown>>;
export declare const hdfResultsSchema: Readonly<Record<string, unknown>>;
export declare const hdfSystemSchema: Readonly<Record<string, unknown>>;
export declare const amendmentsSchema: Readonly<Record<string, unknown>>;
export declare const commonSchema: Readonly<Record<string, unknown>>;
export declare const comparisonSchema: Readonly<Record<string, unknown>>;
export declare const componentSchema: Readonly<Record<string, unknown>>;
export declare const dataFlowSchema: Readonly<Record<string, unknown>>;
export declare const extensionsSchema: Readonly<Record<string, unknown>>;
export declare const parameterSchema: Readonly<Record<string, unknown>>;
export declare const planSchema: Readonly<Record<string, unknown>>;
export declare const platformSchema: Readonly<Record<string, unknown>>;
export declare const resultSchema: Readonly<Record<string, unknown>>;
export declare const runnerSchema: Readonly<Record<string, unknown>>;
export declare const statisticsSchema: Readonly<Record<string, unknown>>;
export declare const systemSchema: Readonly<Record<string, unknown>>;
export declare const targetSchema: Readonly<Record<string, unknown>>;

// Re-export all types from hdf-results (includes most common types)
export * from './ts/hdf-results.js';

// Re-export baseline-only types (interfaces not in hdf-results).
// No export * from hdf-baseline — its enums (HashAlgorithm, Severity) duplicate
// hdf-results and cause ambiguous-export collisions.
export type { HdfBaseline, BaselineRequirement } from './ts/hdf-baseline.js';

// Re-export comparison-specific types (interfaces and enums not in hdf-results).
// No export * from hdf-comparison — shared types duplicate hdf-results.
export type {
  HdfComparison, RequirementDiff, ComparisonSummary, Source,
  Annotation, BaselineDiff, BaselineRef, ComponentDiff, FieldChange, MatchingConfig,
  PackageDiff, ScannerConflict, SeverityBreakdown, StateCounts, PerSourceSummary,
  Value,
} from './ts/hdf-comparison.js';
export {
  AnnotationCategory, BaselineDiffState, ChangeReason, ComparisonMode,
  ConflictResolution, FormatVersion, MatchStrategy, Op, OriginalFormat,
  PackageDiffState, RequirementState, SourceRole, Type,
} from './ts/hdf-comparison.js';

// Re-export system types
// No Component re-export — it's already exported by hdf-results.js via export *
export type {
  HdfSystem, InputOverride, ControlDesignation, DataFlow,
} from './ts/hdf-system.js';
export {
  AuthorizationStatus, BoundaryDescription, CategorizationLevel, Designation, Direction,
} from './ts/hdf-system.js';

// Re-export plan types
export type {
  HdfPlan, Assessment, Schedule, RunnerConfig,
} from './ts/hdf-plan.js';
export {
  PlanType,
} from './ts/hdf-plan.js';

// Re-export amendments types
// No OverrideType enum — already exported by hdf-results via export *.
export type {
  HdfAmendments, StandaloneOverride,
} from './ts/hdf-amendments.js';

// Re-export evidence-package types
export type {
  HdfEvidencePackage, ContentReference, CompletenessCheck, SBOMCoverage,
} from './ts/hdf-evidence-package.js';
export {
  ContentType,
} from './ts/hdf-evidence-package.js';

// Re-export helper functions
export * from './helpers.js';
