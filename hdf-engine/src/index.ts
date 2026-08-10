// @mitre/hdf-engine — shared, schema-typed read-side engines for HDF documents
// (detect, query, compliance, and future read-side engines). Consumed as a
// library by the CLI and the MCP; sibling to @mitre/hdf-diff. See ADR-0007.

/** Library version, kept on the workspace lockstep. */
export const engineVersion = '3.5.0';

// Detection engine (peer of hdf-engine/go/detect.go).
export { detect, type HdfDocType } from './detect.js';

// Query engine (peer of hdf-engine/go/filter.go).
export { filter, type FilterOptions, type Match } from './query.js';

// Document loader core (peer of hdf-engine/go/loader.go).
export { load, detectFormat, type InputFormat, type LoadResult } from './loader.js';

// Evidence-verify engine (peer of hdf-engine/go/evidence.go).
export {
  parseEvidencePackage,
  verifyChecksums,
  plannedBaselineRefs,
  coveredBaselineNames,
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
