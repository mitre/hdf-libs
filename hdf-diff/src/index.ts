// Types
export type {
  ChangeReason,
  RequirementState,
  FieldChange,
  RequirementDiff,
  ComponentDiff,
  ComparisonSummary,
  BaselineDiff,
  Source,
  Annotation,
  MatchingConfig,
  HdfComparison,
} from './types.js';

// Backward-compatibility aliases
export type {
  DiffStatus,
  DiffSummary,
  HdfDiff,
} from './types.js';

// Diff engine
export { diffHdf, diffBaselines, diffSystems } from './diff.js';
export type { DiffOptions } from './diff.js';

// Status utilities
export {
  computeEffectiveStatus,
  classifyChangeReasons,
  classifyDiffStatus,
} from './status.js';

// Summary
export { computeSummary } from './summary.js';

// Normalization (v1 → v2)
export { isV1Format, normalizeToV2 } from './normalize.js';

// Matching strategies
export {
  matchRequirements,
  createExactIdStrategy,
  createMappedIdStrategy,
  createCciMatchStrategy,
  createFuzzyTitleStrategy,
  tokenize,
  jaccardSimilarity,
} from './matching/index.js';
export type {
  MatchResult,
  MatchPair,
  MatchStrategy,
  MatchOptions,
} from './matching/index.js';

// Schema validation
export { validateComparison } from './validate.js';
export type { ValidationResult } from './validate.js';

// Exit codes
export {
  EXIT_IDENTICAL,
  EXIT_DIFFERENCES,
  EXIT_ERROR,
  EXIT_DETAILED_IDENTICAL,
  EXIT_DETAILED_ERROR,
  EXIT_DETAILED_FIXES_ONLY,
  EXIT_DETAILED_REGRESSIONS_ONLY,
  EXIT_DETAILED_MIXED,
  EXIT_DETAILED_BASELINE_CHANGED,
  EXIT_DETAILED_DRIFT_ONLY,
  computeExitCode,
  computeDetailedExitCode,
} from './exit-codes.js';

// Renderers
export { render, renderJson, renderMarkdown, renderTerminal, renderCsv } from './renderers/index.js';
export type { DetailLevel, RenderOptions } from './renderers/types.js';

// SBOM comparison
export { diffSboms } from './sbom.js';
export type { PackageDiff, SbomDiffResult } from './sbom.js';
