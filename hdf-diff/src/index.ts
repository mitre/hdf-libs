// Types
export type {
  ChangeReason,
  RequirementState,
  FieldChange,
  RequirementDiff,
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
export { diffHdf } from './diff.js';
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

// Renderers
export { render, renderJson, renderMarkdown, renderTerminal, renderCsv } from './renderers/index.js';
export type { DetailLevel, RenderOptions } from './renderers/types.js';
