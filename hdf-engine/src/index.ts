// @mitre/hdf-engine — shared, schema-typed read-side engines for HDF documents
// (detect, query, compliance, and future read-side engines). Consumed as a
// library by the CLI and the MCP; sibling to @mitre/hdf-diff. See ADR-0007.

/** Library version, kept on the workspace lockstep (see version.ts). */
export { engineVersion } from './version.js';

// Merge engine (peer of hdf-engine/go/merge.go; ADR-0016).
export {
  merge,
  LABEL_TOOL,
  LABEL_TOOL_VERSION,
  LABEL_SOURCE_DOCUMENT,
  type MergeSource,
  type MergeResult,
  type MergeWarning,
  type MergeWarningKind,
} from './merge.js';

// Detection engine (peer of hdf-engine/go/detect.go).
export { detect, type HdfDocType } from './detect.js';

// Query engine (peer of hdf-engine/go/filter.go).
export { filter, type FilterOptions, type Match } from './query.js';

// Threshold rules: a filter predicate plus a bound, for the policies the fixed
// status x severity grid cannot express.
export {
  evaluateRules,
  evaluate,
  type ThresholdInput,
  type ThresholdRule,
  type RulePredicate,
  type RuleOptions,
} from './rules.js';
export { validateGrid, ruleRefusal } from './compliance.js';
export {
  validStatus,
  validSeverity,
  normalizeFilterValue,
  normalizeKey,
  STATUS_VALUES,
  SEVERITY_VALUES,
} from './vocabulary.js';

// Document loader core (peer of hdf-engine/go/loader.go).
export { load, detectFormat, type InputFormat, type LoadResult } from './loader.js';

// Evidence-verify engine (peer of hdf-engine/go/evidence.go).
export {
  parseEvidencePackage,
  verifyChecksums,
  plannedBaselineRefs,
  coveredBaselineNames,
  coveredBaselinesInPackage,
  agentOverridesInPackage,
  completeness,
  type ChecksumStatus,
  type EvidenceContent,
  type ChecksumResult,
  type CompletenessResult,
  type FetchFn,
} from './evidence.js';

// Compliance & threshold engine (peer of hdf-engine/go/compliance.go).
export {
  countControlsByStatusSeverity,
  countControlsByStatus,
  agentOverrideCount,
  mapControlIDs,
  mapControlIDsByStatus,
  calculateCompliance,
  validateThresholds,
  overallStatus,
  deriveSeverity,
  type StatusCounts,
  type SeverityCounts,
  type ControlIDMapping,
  type ThresholdConfig,
  type ThresholdSeverity,
  type ThresholdBound,
  type ComplianceBound,
} from './compliance.js';
