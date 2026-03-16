import type {
  HdfComparison,
  RequirementDiff,
  BaselineDiff,
  FieldChange,
  Source,
} from './types.js';
import { computeEffectiveStatus, classifyChangeReasons, classifyDiffStatus } from './status.js';
import { computeSummary } from './summary.js';
import { normalizeToV2 } from './normalize.js';
import { matchRequirements } from './matching/index.js';
import type { MatchOptions } from './matching/index.js';
import { validateComparison } from './validate.js';

/**
 * Options for configuring the diff behavior.
 */
export interface DiffOptions {
  /** Fields to track for field-level diffs (default: ['impact', 'severity', 'tags']) */
  trackedFields?: string[];
  /** Comparison mode (default: 'temporal') */
  comparisonMode?: 'temporal' | 'baseline' | 'fleet' | 'multiSource';
  /** Primary matching strategy name (default: 'exactId') */
  matchStrategy?: string;
  /** Fallback strategy names, applied in order to remaining unmatched requirements */
  fallbackStrategies?: string[];
  /** Mapping table for the 'mappedId' strategy (old ID -> new ID) */
  mappingTable?: Record<string, string>;
  /** Minimum confidence threshold for fuzzy matching (default: 0.6) */
  minConfidence?: number;
  /** Validate output against hdf-comparison schema. Default: false (performance). */
  validateOutput?: boolean;
}

const DEFAULT_TRACKED_FIELDS = ['impact', 'severity', 'tags'];

interface BaselineLike {
  name: string;
  version?: string;
  requirements: RequirementLike[];
}

interface RequirementLike {
  id: string;
  title?: string;
  impact: number;
  [key: string]: unknown;
}

/**
 * Extract a dataSource label from a document, if available.
 * Looks for `dataSource.name` in the raw (pre-normalized) document.
 */
function extractDataSourceLabel(doc: Record<string, unknown>): string | undefined {
  const ds = doc['dataSource'] as Record<string, unknown> | undefined;
  if (ds && typeof ds['name'] === 'string') {
    return ds['name'];
  }
  return undefined;
}

/**
 * Build MatchOptions from DiffOptions, extracting the matching-related fields.
 */
function buildMatchOptions(options?: DiffOptions): MatchOptions {
  return {
    strategy: options?.matchStrategy,
    fallbackStrategies: options?.fallbackStrategies,
    mappingTable: options?.mappingTable,
    minConfidence: options?.minConfidence,
  };
}

/**
 * Determine the primary strategy name for the matching config output.
 */
function resolveStrategyName(options?: DiffOptions): string {
  return options?.matchStrategy ?? 'exactId';
}

/**
 * Compare two HDF results documents and produce a structured comparison.
 *
 * Requirements are matched using a configurable matching strategy (default: exact ID).
 * Baselines are matched by `name`.
 *
 * For fleet mode, `newResults` can be an array of documents, each compared
 * pairwise against `oldResults` (the reference).
 */
export function diffHdf(
  oldResults: Record<string, unknown>,
  newResults: Record<string, unknown> | Record<string, unknown>[],
  options?: DiffOptions,
): HdfComparison {
  const trackedFields = options?.trackedFields ?? DEFAULT_TRACKED_FIELDS;
  const comparisonMode = options?.comparisonMode ?? 'temporal';
  const matchOpts = buildMatchOptions(options);

  // Validate array inputs up front (applies to all modes)
  if (Array.isArray(newResults)) {
    if (newResults.length === 0) {
      throw new Error('newResults array must not be empty');
    }
    if (comparisonMode !== 'fleet' && newResults.length > 1) {
      throw new Error(
        `Mode '${comparisonMode}' expects a single document, got ${newResults.length}. Use 'fleet' mode for multiple documents.`
      );
    }
  }

  // Fleet mode: compare reference against each system
  if (comparisonMode === 'fleet') {
    return diffFleet(oldResults, newResults, trackedFields, matchOpts);
  }

  // Non-fleet modes: newResults must be a single document
  const newDoc = Array.isArray(newResults) ? newResults[0]! : newResults;

  // Normalize v1 (InSpec exec-json) to v2 if needed
  const oldNormalized = normalizeToV2(oldResults);
  const newNormalized = normalizeToV2(newDoc);

  const oldTimestamp = oldNormalized['timestamp'] as string | undefined;
  const newTimestamp = newNormalized['timestamp'] as string | undefined;

  // Build sources metadata based on mode
  const sources = buildSources(comparisonMode, oldResults, newDoc, oldTimestamp, newTimestamp);

  // Compute baseline and requirement diffs
  const { baselineDiffs, requirementDiffs } = comparePair(
    oldNormalized, newNormalized, oldTimestamp, newTimestamp, trackedFields, matchOpts,
  );

  // Sort by id
  requirementDiffs.sort((a, b) => a.id.localeCompare(b.id));

  // Extract drift: unchanged requirements with metadata changes
  const drift = extractDrift(requirementDiffs);

  const comparison: HdfComparison = {
    formatVersion: '1.0.0',
    comparisonMode,
    timestamp: new Date().toISOString(),
    sources,
    matching: {
      primaryStrategy: resolveStrategyName(options),
    },
    summary: computeSummary(requirementDiffs),
    baselineDiffs,
    requirementDiffs,
    drift,
  };

  if (options?.validateOutput) {
    const result = validateComparison(comparison);
    // Safety net: diffHdf always produces valid output by construction.
    // This branch is unreachable in normal operation but guards against future regressions.
    /* c8 ignore start */
    if (!result.valid) {
      throw new Error(`Output validation failed: ${result.errors?.join(', ')}`);
    }
    /* c8 ignore stop */
  }

  return comparison;
}

/**
 * Build source metadata entries based on comparison mode.
 */
function buildSources(
  mode: 'temporal' | 'baseline' | 'multiSource',
  oldDoc: Record<string, unknown>,
  newDoc: Record<string, unknown>,
  oldTimestamp?: string,
  newTimestamp?: string,
): Source[] {
  switch (mode) {
    case 'baseline':
      return [
        { role: 'golden', label: 'Golden baseline', assessmentTimestamp: oldTimestamp },
        { role: 'new', label: 'Current scan', assessmentTimestamp: newTimestamp },
      ];

    case 'multiSource': {
      const oldLabel = extractDataSourceLabel(oldDoc) ?? 'Old evaluation';
      const newLabel = extractDataSourceLabel(newDoc) ?? 'New evaluation';
      return [
        { role: 'old', label: oldLabel, assessmentTimestamp: oldTimestamp },
        { role: 'new', label: newLabel, assessmentTimestamp: newTimestamp },
      ];
    }

    case 'temporal':
    default:
      return [
        { role: 'old', label: 'Old evaluation', assessmentTimestamp: oldTimestamp },
        { role: 'new', label: 'New evaluation', assessmentTimestamp: newTimestamp },
      ];
  }
}

/**
 * Fleet mode: compare a reference document against one or more system documents.
 * Each system is compared pairwise against the reference; all diffs are collected
 * into a single result with `sourceIndex` set on each RequirementDiff.
 */
function diffFleet(
  referenceDoc: Record<string, unknown>,
  newResults: Record<string, unknown> | Record<string, unknown>[],
  trackedFields: string[],
  matchOpts: MatchOptions,
): HdfComparison {
  const systems = Array.isArray(newResults) ? newResults : [newResults];

  const refNormalized = normalizeToV2(referenceDoc);
  const refTimestamp = refNormalized['timestamp'] as string | undefined;

  // Build sources, compare each system against the reference, and collect diffs
  // in a single pass — each system document is normalized exactly once.
  const sources: Source[] = [
    { role: 'reference', label: 'Reference', assessmentTimestamp: refTimestamp },
  ];
  const allRequirementDiffs: RequirementDiff[] = [];
  const allBaselineDiffs: BaselineDiff[] = [];
  // Deduplicate baseline diffs by name: first-wins. In fleet mode, every system
  // is compared against the same reference, so the first occurrence of a
  // BaselineDiff for a given baseline name is representative. BaselineDiff does
  // not carry a sourceIndex in v1 of the schema, so per-system baseline tracking
  // is deferred to a future version.
  const seenBaselineNames = new Set<string>();

  for (let i = 0; i < systems.length; i++) {
    const sysNormalized = normalizeToV2(systems[i]!);
    const sysTimestamp = sysNormalized['timestamp'] as string | undefined;
    const sourceIndex = i + 1;

    // Build the source entry for this system
    sources.push({
      role: 'system',
      label: `System ${sourceIndex}`,
      assessmentTimestamp: sysTimestamp,
    });

    const { baselineDiffs, requirementDiffs } = comparePair(
      refNormalized, sysNormalized, refTimestamp, sysTimestamp, trackedFields, matchOpts,
    );

    // Tag each requirement diff with its source index
    for (const rd of requirementDiffs) {
      rd.sourceIndex = sourceIndex;
      allRequirementDiffs.push(rd);
    }

    // Collect baseline diffs (first-wins dedup; see comment above)
    for (const bd of baselineDiffs) {
      if (!seenBaselineNames.has(bd.name)) {
        seenBaselineNames.add(bd.name);
        allBaselineDiffs.push(bd);
      }
    }
  }

  // Sort by id, then by sourceIndex
  allRequirementDiffs.sort((a, b) => {
    const idCmp = a.id.localeCompare(b.id);
    if (idCmp !== 0) return idCmp;
    /* c8 ignore next -- sourceIndex is always set in fleet mode; ?? 0 is defensive typing */
    return (a.sourceIndex ?? 0) - (b.sourceIndex ?? 0);
  });

  // Extract drift: unchanged requirements with metadata changes
  const drift = extractDrift(allRequirementDiffs);

  return {
    formatVersion: '1.0.0',
    comparisonMode: 'fleet',
    timestamp: new Date().toISOString(),
    sources,
    matching: {
      primaryStrategy: matchOpts.strategy ?? 'exactId',
    },
    summary: computeSummary(allRequirementDiffs),
    baselineDiffs: allBaselineDiffs,
    requirementDiffs: allRequirementDiffs,
    drift,
  };
}

/**
 * Extract drift entries from requirement diffs.
 *
 * Drift = requirements whose effective status is unchanged but whose metadata
 * changed (tags, descriptions, impact score, etc.). These are the "silent"
 * changes that don't affect pass/fail outcome but still matter for auditing.
 *
 * Returns shallow copies so drift entries are independent of requirementDiffs.
 */
function extractDrift(requirementDiffs: RequirementDiff[]): RequirementDiff[] {
  return requirementDiffs
    .filter(r => r.state === 'unchanged' && r.changeReasons.length > 0)
    .map(r => ({ ...r }));
}

/**
 * Core pairwise comparison between two normalized HDF documents.
 * Returns baseline diffs and requirement diffs without sorting or wrapping.
 *
 * Uses the pluggable matching system to pair requirements between evaluations.
 */
function comparePair(
  oldNormalized: Record<string, unknown>,
  newNormalized: Record<string, unknown>,
  oldTimestamp: string | undefined,
  newTimestamp: string | undefined,
  trackedFields: string[],
  matchOpts: MatchOptions,
): { baselineDiffs: BaselineDiff[]; requirementDiffs: RequirementDiff[] } {
  const oldBaselines = (oldNormalized['baselines'] as BaselineLike[] | undefined) ?? [];
  const newBaselines = (newNormalized['baselines'] as BaselineLike[] | undefined) ?? [];

  // Build baseline maps by name
  const oldBaselineMap = new Map<string, BaselineLike>();
  for (const b of oldBaselines) {
    oldBaselineMap.set(b.name, b);
  }
  const newBaselineMap = new Map<string, BaselineLike>();
  for (const b of newBaselines) {
    newBaselineMap.set(b.name, b);
  }

  // Compute baseline diffs
  const allBaselineNames = new Set([...oldBaselineMap.keys(), ...newBaselineMap.keys()]);
  const baselineDiffs: BaselineDiff[] = [];

  for (const name of allBaselineNames) {
    const oldB = oldBaselineMap.get(name);
    const newB = newBaselineMap.get(name);

    if (oldB && newB) {
      const versionChanged = oldB.version !== newB.version;
      baselineDiffs.push({
        name,
        oldVersion: oldB.version,
        newVersion: newB.version,
        state: versionChanged ? 'updated' : 'unchanged',
      });
    } else if (oldB && !newB) {
      baselineDiffs.push({
        name,
        oldVersion: oldB.version,
        state: 'absent',
      });
    } else if (!oldB && newB) {
      baselineDiffs.push({
        name,
        newVersion: newB.version,
        state: 'new',
      });
    }
  }

  // Collect all requirements across all baselines
  const oldReqs: Record<string, unknown>[] = [];
  for (const baseline of oldBaselines) {
    for (const req of baseline.requirements) {
      oldReqs.push(req as unknown as Record<string, unknown>);
    }
  }
  const newReqs: Record<string, unknown>[] = [];
  for (const baseline of newBaselines) {
    for (const req of baseline.requirements) {
      newReqs.push(req as unknown as Record<string, unknown>);
    }
  }

  // Use the matching system to pair requirements
  const matchResult = matchRequirements(oldReqs, newReqs, matchOpts);

  // Build requirement diffs from match results
  const requirementDiffs: RequirementDiff[] = [];

  // Matched pairs
  for (const pair of matchResult.matched) {
    const oldReq = pair.oldReq as RequirementLike;
    const newReq = pair.newReq as RequirementLike;
    /* c8 ignore next -- id is always a string on RequirementLike; ?? is defensive typing */
    const id = (newReq.id ?? oldReq.id) as string;

    const oldStatus = computeEffectiveStatus(
      oldReq as unknown as Record<string, unknown>,
      oldTimestamp,
    );
    const newStatus = computeEffectiveStatus(
      newReq as unknown as Record<string, unknown>,
      newTimestamp,
    );

    const diffState = classifyDiffStatus(oldStatus, newStatus);
    const changeReasons = classifyChangeReasons(
      oldReq as unknown as Record<string, unknown>,
      newReq as unknown as Record<string, unknown>,
      oldTimestamp,
      newTimestamp,
    );

    const fieldChanges = computeFieldChanges(oldReq, newReq, trackedFields);

    requirementDiffs.push({
      id,
      title: newReq.title ?? oldReq.title,
      state: diffState,
      oldEffectiveStatus: oldStatus,
      newEffectiveStatus: newStatus,
      changeReasons,
      oldImpact: oldReq.impact,
      newImpact: newReq.impact,
      fieldChanges,
      before: oldReq as unknown as Record<string, unknown>,
      after: newReq as unknown as Record<string, unknown>,
      matchStrategy: pair.strategy,
      matchConfidence: pair.confidence,
    });
  }

  // Unmatched old requirements (absent)
  for (const req of matchResult.unmatchedOld) {
    const oldReq = req as RequirementLike;
    const id = oldReq.id as string;
    const oldStatus = computeEffectiveStatus(
      oldReq as unknown as Record<string, unknown>,
      oldTimestamp,
    );
    requirementDiffs.push({
      id,
      title: oldReq.title,
      state: 'absent',
      oldEffectiveStatus: oldStatus,
      changeReasons: [],
      oldImpact: oldReq.impact,
      fieldChanges: [],
      before: oldReq as unknown as Record<string, unknown>,
      after: null,
    });
  }

  // Unmatched new requirements (new)
  for (const req of matchResult.unmatchedNew) {
    const newReq = req as RequirementLike;
    const id = newReq.id as string;
    const newStatus = computeEffectiveStatus(
      newReq as unknown as Record<string, unknown>,
      newTimestamp,
    );
    requirementDiffs.push({
      id,
      title: newReq.title,
      state: 'new',
      newEffectiveStatus: newStatus,
      changeReasons: [],
      newImpact: newReq.impact,
      fieldChanges: [],
      before: null,
      after: newReq as unknown as Record<string, unknown>,
    });
  }

  return { baselineDiffs, requirementDiffs };
}

/**
 * Compute field-level changes for tracked fields between two requirements.
 * Uses JSON Patch-like op/path format.
 */
function computeFieldChanges(
  oldReq: RequirementLike,
  newReq: RequirementLike,
  trackedFields: string[],
): FieldChange[] {
  const changes: FieldChange[] = [];

  for (const field of trackedFields) {
    const oldVal = oldReq[field];
    const newVal = newReq[field];

    // Deep comparison for objects/arrays
    if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
      if (oldVal === undefined && newVal !== undefined) {
        changes.push({
          op: 'add',
          path: field,
          newValue: newVal,
        });
      } else if (oldVal !== undefined && newVal === undefined) {
        changes.push({
          op: 'remove',
          path: field,
          oldValue: oldVal,
        });
      } else {
        changes.push({
          op: 'replace',
          path: field,
          oldValue: oldVal,
          newValue: newVal,
        });
      }
    }
  }

  return changes;
}
