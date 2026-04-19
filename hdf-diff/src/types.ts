/**
 * Why a requirement's effective status changed between two evaluations.
 *
 * Aligned with the hdf-comparison schema's Change_Reason enum:
 * - resultChanged: The underlying test results differ (e.g., a fix was deployed)
 * - overrideAdded: A new statusOverride (waiver/attestation) was added
 * - overrideExpired: A statusOverride present in the old scan has expired by the new scan's timestamp
 * - overrideRemoved: A statusOverride was removed between scans
 * - overrideModified: An existing statusOverride was modified (reserved for future use)
 * - impactChanged: The impact score changed (e.g., from 0.7 to 0.0 means N/A)
 * - baselineUpgraded: The baseline version changed (reserved for future use)
 * - controlMapped: A control was mapped to a different framework (reserved for future use)
 * - scannerChanged: A different scanner was used (reserved for future use)
 * - targetChanged: The scan target changed (reserved for future use)
 * - configChanged: The scan configuration changed (reserved for future use)
 * - metadataChanged: Non-impact baseline metadata changed (tags, descriptions, title, etc.)
 */
export type ChangeReason =
  | 'resultChanged'
  | 'overrideAdded'
  | 'overrideExpired'
  | 'overrideRemoved'
  | 'overrideModified'
  | 'impactChanged'
  | 'baselineUpgraded'
  | 'controlMapped'
  | 'scannerChanged'
  | 'targetChanged'
  | 'configChanged'
  | 'metadataChanged'
  | 'dispositionChanged'
  | 'effectiveImpactChanged';

/**
 * Classification of how a requirement's state changed between evaluations.
 * Uses SARIF-inspired vocabulary.
 *
 * - new: Requirement exists only in the new evaluation (was "added")
 * - absent: Requirement exists only in the old evaluation (was "removed")
 * - unchanged: Same effective status in both evaluations
 * - updated: Status changed but doesn't fit fixed/regressed (was "changed")
 * - fixed: Was failing/error, now passing
 * - regressed: Was passing, now failing/error
 * - moved: Requirement ID changed but content is the same (future use)
 * - split: One requirement became multiple (future use)
 * - merged: Multiple requirements became one (future use)
 */
export type RequirementState =
  | 'new'
  | 'absent'
  | 'unchanged'
  | 'updated'
  | 'fixed'
  | 'regressed'
  | 'moved'
  | 'split'
  | 'merged';

/**
 * A field-level difference on a requirement, following JSON Patch-like conventions.
 */
export interface FieldChange {
  /** The operation type: add, remove, or replace */
  op: 'add' | 'remove' | 'replace';
  /** Dot-notation path to the changed field (e.g., 'impact', 'tags.cci') */
  path: string;
  /** Value in the old evaluation (undefined for 'add' operations) */
  oldValue?: unknown;
  /** Value in the new evaluation (undefined for 'remove' operations) */
  newValue?: unknown;
}

/**
 * The diff for a single requirement across two evaluations.
 */
export interface RequirementDiff {
  /** The requirement ID (e.g., 'SV-238196') */
  id: string;
  /** Classification of the change */
  state: RequirementState;
  /** Why the status changed — empty array if unchanged */
  changeReasons: ChangeReason[];

  /** Full snapshot of the requirement from the old evaluation (null when state = 'new') */
  before: Record<string, unknown> | null;
  /** Full snapshot of the requirement from the new evaluation (null when state = 'absent') */
  after: Record<string, unknown> | null;

  /** The requirement title (from whichever evaluation has it) */
  title?: string;
  /** Effective status in the old evaluation (undefined if new) */
  oldEffectiveStatus?: string;
  /** Effective status in the new evaluation (undefined if absent) */
  newEffectiveStatus?: string;
  /** Impact in the old evaluation */
  oldImpact?: number;
  /** Impact in the new evaluation */
  newImpact?: number;

  /** Field-level diffs for non-status fields */
  fieldChanges: FieldChange[];

  /** The matching strategy that paired this requirement (e.g., 'exactId') */
  matchStrategy?: string;
  /** Confidence of the match (0.0-1.0) */
  matchConfidence?: number;

  /** Index into the sources array for fleet mode */
  sourceIndex?: number;
}

/**
 * Summary counts for the comparison.
 */
export interface ComparisonSummary {
  /** Requirements that went from failing/error to passing */
  fixed: number;
  /** Requirements that went from passing to failing/error */
  regressed: number;
  /** Requirements present only in the new evaluation (was "added") */
  new: number;
  /** Requirements present only in the old evaluation (was "removed") */
  absent: number;
  /** Requirements with the same effective status */
  unchanged: number;
  /** Requirements whose status changed in a way other than fixed/regressed (was "changed") */
  updated: number;
  /** Total unique requirements across both evaluations */
  total: number;
  /** Number of requirements matched between old and new */
  matchedCount: number;
  /** Number of requirements only in old (unmatched) */
  unmatchedOldCount: number;
  /** Number of requirements only in new (unmatched) */
  unmatchedNewCount: number;
}

/**
 * The diff for a single component across two system documents.
 * Used in systemDrift comparison mode.
 */
export interface ComponentDiff {
  /** Component name */
  name: string;
  /** Classification of the change: new, absent, unchanged, or updated */
  state: 'new' | 'absent' | 'unchanged' | 'updated';
  /** Component snapshot from the old system (null when state = 'new') */
  before: Record<string, unknown> | null;
  /** Component snapshot from the new system (null when state = 'absent') */
  after: Record<string, unknown> | null;
  /** Field-level diffs between old and new component */
  fieldChanges: FieldChange[];
}

/**
 * The diff for a single baseline across two evaluations.
 */
export interface BaselineDiff {
  /** Baseline name */
  name: string;
  /** Version in the old evaluation */
  oldVersion?: string;
  /** Version in the new evaluation */
  newVersion?: string;
  /** Whether this baseline was new, absent, updated, or unchanged */
  state: 'new' | 'absent' | 'updated' | 'unchanged';
}

/**
 * Metadata about a source document used in the comparison.
 */
export interface Source {
  /** Role of the source in the comparison */
  role: 'old' | 'new' | 'golden' | 'reference' | 'system';
  /** Human-readable label */
  label: string;
  /** URI to the source document */
  uri?: string;
  /** Original format of the source (e.g., 'hdf-results-v2', 'inspec-exec-json-v1') */
  originalFormat?: string;
  /** Assessment timestamp from the source document */
  assessmentTimestamp?: string;
}

/**
 * An annotation attached to a requirement diff.
 */
export interface Annotation {
  /** Human-readable label */
  label: string;
  /** Description of the annotation */
  text: string;
  /** When the annotation was created */
  timestamp?: string;
}

/**
 * The top-level comparison result comparing two or more HDF evaluations.
 */
export interface HdfComparison {
  /** Schema version for the comparison format */
  formatVersion: '1.0.0';
  /** The mode of comparison */
  comparisonMode: 'temporal' | 'baseline' | 'fleet' | 'multiSource' | 'baselineEvolution' | 'systemDrift';
  /** When the comparison was generated */
  timestamp?: string;
  /** Source documents used in the comparison */
  sources: Source[];
  /** Matching configuration used */
  matching?: MatchingConfig;
  /** Aggregate counts */
  summary: ComparisonSummary;
  /** Per-baseline diffs */
  baselineDiffs: BaselineDiff[];
  /** Per-requirement diffs, sorted by id */
  requirementDiffs: RequirementDiff[];
  /** Per-component diffs (systemDrift mode only) */
  componentDiffs?: ComponentDiff[];
  /** Per-package diffs from embedded SBOM comparison (systemDrift mode only) */
  packageDiffs?: import('./sbom.js').PackageDiff[];
  /** URI identifying the system being compared (systemDrift mode only) */
  systemRef?: string;
  /** Requirements that drifted from a golden baseline (future use) */
  drift?: RequirementDiff[];
  /** Annotations keyed by requirement ID */
  annotations?: Record<string, Annotation>;
  /** Extension data for custom integrations */
  extensions?: Record<string, unknown>;
}

/**
 * Configuration for how requirements are matched between evaluations.
 */
export interface MatchingConfig {
  /** The primary strategy used for matching requirements across sources */
  primaryStrategy: string;
  /** Minimum confidence threshold for a match */
  confidenceThreshold?: number;
}

// ── Backward-compatibility aliases ───────────────────────────────────
// These allow gradual migration from old type names.

/** @deprecated Use RequirementState instead */
export type DiffStatus = RequirementState;

/** @deprecated Use ComparisonSummary instead */
export type DiffSummary = ComparisonSummary;

/** @deprecated Use HdfComparison instead */
export type HdfDiff = HdfComparison;
