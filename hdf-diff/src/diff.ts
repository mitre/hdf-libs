import type {
  HdfComparison,
  RequirementDiff,
  BaselineDiff,
  ComponentDiff,
  FieldChange,
  Source,
} from './types.js';
import { computeEffectiveStatus, classifyChangeReasons, classifyDiffStatus } from './status.js';
import { computeSummary } from './summary.js';
import { normalizeToV2 } from './normalize.js';
import { matchRequirements } from './matching/index.js';
import type { MatchOptions } from './matching/index.js';
import { validateComparison } from './validate.js';
import { diffSboms } from './sbom.js';
import { parseCvssVector as parseCvssVectorUtil } from '@mitre/hdf-utilities';
import type { PackageDiff } from './sbom.js';

/**
 * Options for configuring the diff behavior.
 */
export interface DiffOptions {
  /** Fields to track for field-level diffs (default: ['impact', 'severity', 'tags']) */
  trackedFields?: string[];
  /** Comparison mode (default: 'temporal') */
  comparisonMode?: 'temporal' | 'baseline' | 'fleet' | 'multiSource' | 'baselineEvolution' | 'systemDrift';
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
  let comparisonMode = options?.comparisonMode ?? 'temporal';
  const matchOpts = buildMatchOptions(options);

  // Auto-detect baseline evolution mode when both inputs are baseline documents
  // (have requirements[] but no baselines[], targets[], or statistics[])
  if (!options?.comparisonMode && !Array.isArray(newResults)) {
    if (isBaselineDocument(oldResults) && isBaselineDocument(newResults)) {
      comparisonMode = 'baselineEvolution';
    } else if (isSystemDocument(oldResults) && isSystemDocument(newResults)) {
      comparisonMode = 'systemDrift';
    }
  }

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

  // Baseline evolution mode: compare two baseline documents
  if (comparisonMode === 'baselineEvolution') {
    const newDoc = Array.isArray(newResults) ? newResults[0]! : newResults;
    return diffBaselines(oldResults, newDoc, options);
  }

  // System drift mode: compare two system documents
  if (comparisonMode === 'systemDrift') {
    const newDoc = Array.isArray(newResults) ? newResults[0]! : newResults;
    return diffSystems(oldResults, newDoc, options);
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

/** Field names handled by dedicated CVE-ecosystem diff handlers (not generic JSON compare). */
const CVE_ECOSYSTEM_FIELDS = new Set(['cvss', 'epss', 'kev', 'cwe', 'affectedPackages']);

/**
 * Compute field-level changes for tracked fields between two requirements.
 * Uses JSON Patch-like op/path format.
 *
 * Always runs the CVE-ecosystem handlers (cvss, epss, kev, cwe, affectedPackages)
 * in addition to whatever scalar fields are in trackedFields, since these
 * structured types need richer diff than generic JSON comparison provides.
 */
function computeFieldChanges(
  oldReq: RequirementLike,
  newReq: RequirementLike,
  trackedFields: string[],
): FieldChange[] {
  const changes: FieldChange[] = [];

  for (const field of trackedFields) {
    // CVE-ecosystem fields are handled below by dedicated handlers
    if (CVE_ECOSYSTEM_FIELDS.has(field)) continue;

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

  // Always run CVE-ecosystem handlers — these fields are part of the v3.x
  // Evaluated_Requirement structured types and need typed diffing regardless
  // of the trackedFields setting.
  changes.push(...diffCvssArray(oldReq['cvss'], newReq['cvss']));
  changes.push(...diffEpss(oldReq['epss'], newReq['epss']));
  changes.push(...diffKev(oldReq['kev'], newReq['kev']));
  changes.push(...diffCweSet(oldReq['cwe'], newReq['cwe']));
  changes.push(...diffAffectedPackages(oldReq['affectedPackages'], newReq['affectedPackages']));

  return changes;
}

// ── CVE-ecosystem diff handlers ─────────────────────────────────────────

interface CvssEntry {
  source?: string;
  baseScore?: number;
  baseSeverity?: string;
  baseVector?: string;
  threatScore?: number;
  threatVector?: string;
  environmentalScore?: number;
  environmentalVector?: string;
  supplementalVector?: string;
  [key: string]: unknown;
}

const CVSS_VECTOR_FIELDS = [
  'baseVector',
  'threatVector',
  'environmentalVector',
  'supplementalVector',
] as const;

/**
 * Parse a CVSS vector string into a map of metric-code → value.
 *
 * Accepts both v3.x ("CVSS:3.1/AV:N/AC:L/...") and v4.0 ("CVSS:4.0/AV:N/...")
 * shapes, plus partial vectors that omit the version prefix (e.g., the
 * `threatVector` field is conventionally just the threat metrics).
 *
 * Returns `null` for inputs that don't look like CVSS vectors so callers
 * can fall back to a scalar string compare.
 *
 * Delegates to `parseCvssVector` from `@mitre/hdf-utilities` but adapts the
 * return shape: returns null for empty/unparseable inputs so call sites can
 * fall back to scalar string compare.
 */
function parseCvssVector(vec: string): { version?: string; metrics: Map<string, string> } | null {
  if (typeof vec !== 'string' || vec.length === 0) return null;
  const parsed = parseCvssVectorUtil(vec);
  if (parsed.metrics.size === 0) return null;
  return {
    version: parsed.version === 'unknown' ? undefined : parsed.version,
    metrics: parsed.metrics,
  };
}

/**
 * Diff a single pair of cvss entries (same source). Emits per-field changes
 * including decomposed per-metric vector diffs.
 */
function diffCvssEntry(
  source: string,
  oldEntry: CvssEntry,
  newEntry: CvssEntry,
): FieldChange[] {
  const changes: FieldChange[] = [];
  const allKeys = new Set([...Object.keys(oldEntry), ...Object.keys(newEntry)]);

  for (const key of allKeys) {
    if (key === 'source') continue;
    const oldVal = oldEntry[key];
    const newVal = newEntry[key];
    if (JSON.stringify(oldVal) === JSON.stringify(newVal)) continue;

    // Vector fields: decompose into per-metric records when both parse cleanly
    if ((CVSS_VECTOR_FIELDS as readonly string[]).includes(key)) {
      if (typeof oldVal === 'string' && typeof newVal === 'string') {
        const oldParsed = parseCvssVector(oldVal);
        const newParsed = parseCvssVector(newVal);
        if (oldParsed && newParsed) {
          const metricKeys = new Set<string>([
            ...oldParsed.metrics.keys(), ...newParsed.metrics.keys(),
          ]);
          for (const m of metricKeys) {
            const o = oldParsed.metrics.get(m);
            const n = newParsed.metrics.get(m);
            if (o === n) continue;
            if (o === undefined && n !== undefined) {
              changes.push({ op: 'add', path: `cvss[${source}].${key}.${m}`, newValue: n });
            } else if (o !== undefined && n === undefined) {
              changes.push({ op: 'remove', path: `cvss[${source}].${key}.${m}`, oldValue: o });
            } else {
              changes.push({
                op: 'replace', path: `cvss[${source}].${key}.${m}`, oldValue: o, newValue: n,
              });
            }
          }
          continue;
        }
      } else if (oldVal === undefined && typeof newVal === 'string') {
        // Whole vector added — decompose into per-metric add records
        const parsed = parseCvssVector(newVal);
        if (parsed) {
          for (const [m, v] of parsed.metrics) {
            changes.push({ op: 'add', path: `cvss[${source}].${key}.${m}`, newValue: v });
          }
          continue;
        }
      } else if (typeof oldVal === 'string' && newVal === undefined) {
        const parsed = parseCvssVector(oldVal);
        if (parsed) {
          for (const [m, v] of parsed.metrics) {
            changes.push({ op: 'remove', path: `cvss[${source}].${key}.${m}`, oldValue: v });
          }
          continue;
        }
      }
      // Fall through to scalar replace for unparseable / mixed-type cases
    }

    if (oldVal === undefined) {
      changes.push({ op: 'add', path: `cvss[${source}].${key}`, newValue: newVal });
    } else if (newVal === undefined) {
      changes.push({ op: 'remove', path: `cvss[${source}].${key}`, oldValue: oldVal });
    } else {
      changes.push({
        op: 'replace', path: `cvss[${source}].${key}`, oldValue: oldVal, newValue: newVal,
      });
    }
  }

  return changes;
}

/**
 * Diff old vs new cvss[] arrays. Entries are matched by `source` (CVE ID
 * or scoring authority); added/removed entries emit whole-entry add/remove
 * records; matched pairs are decomposed via diffCvssEntry.
 */
function diffCvssArray(oldField: unknown, newField: unknown): FieldChange[] {
  const oldArr = Array.isArray(oldField) ? (oldField as CvssEntry[]) : [];
  const newArr = Array.isArray(newField) ? (newField as CvssEntry[]) : [];
  if (oldArr.length === 0 && newArr.length === 0) return [];

  const oldBySource = new Map<string, CvssEntry>();
  for (const e of oldArr) {
    if (typeof e?.source === 'string') oldBySource.set(e.source, e);
  }
  const newBySource = new Map<string, CvssEntry>();
  for (const e of newArr) {
    if (typeof e?.source === 'string') newBySource.set(e.source, e);
  }

  const changes: FieldChange[] = [];
  const allSources = new Set([...oldBySource.keys(), ...newBySource.keys()]);
  for (const source of allSources) {
    const o = oldBySource.get(source);
    const n = newBySource.get(source);
    if (o && !n) {
      changes.push({ op: 'remove', path: `cvss[${source}]`, oldValue: o });
    } else if (!o && n) {
      changes.push({ op: 'add', path: `cvss[${source}]`, newValue: n });
    } else if (o && n) {
      changes.push(...diffCvssEntry(source, o, n));
    }
  }
  return changes;
}

/** Diff the optional `epss` object (score, percentile, date). */
function diffEpss(oldField: unknown, newField: unknown): FieldChange[] {
  if (oldField === undefined && newField === undefined) return [];
  if (oldField === undefined) {
    return [{ op: 'add', path: 'epss', newValue: newField }];
  }
  if (newField === undefined) {
    return [{ op: 'remove', path: 'epss', oldValue: oldField }];
  }
  if (typeof oldField !== 'object' || typeof newField !== 'object' || oldField === null || newField === null) {
    if (JSON.stringify(oldField) === JSON.stringify(newField)) return [];
    return [{ op: 'replace', path: 'epss', oldValue: oldField, newValue: newField }];
  }
  const oldObj = oldField as Record<string, unknown>;
  const newObj = newField as Record<string, unknown>;
  const changes: FieldChange[] = [];
  const allKeys = new Set([...Object.keys(oldObj), ...Object.keys(newObj)]);
  for (const key of allKeys) {
    const o = oldObj[key];
    const n = newObj[key];
    if (JSON.stringify(o) === JSON.stringify(n)) continue;
    if (o === undefined) {
      changes.push({ op: 'add', path: `epss.${key}`, newValue: n });
    } else if (n === undefined) {
      changes.push({ op: 'remove', path: `epss.${key}`, oldValue: o });
    } else {
      changes.push({ op: 'replace', path: `epss.${key}`, oldValue: o, newValue: n });
    }
  }
  return changes;
}

/**
 * Diff the optional `kev` object. Flips of `inKev` from false→true (or
 * fresh add with `inKev: true`) get an annotated `message` field calling
 * out the CISA KEV catalog inclusion.
 */
function diffKev(oldField: unknown, newField: unknown): FieldChange[] {
  if (oldField === undefined && newField === undefined) return [];
  if (oldField === undefined) {
    const change: FieldChange = { op: 'add', path: 'kev', newValue: newField };
    const nObj = newField as Record<string, unknown> | null;
    if (nObj && nObj['inKev'] === true) {
      const dateAdded = typeof nObj['dateAdded'] === 'string' ? nObj['dateAdded'] : 'unknown date';
      change.message = `Newly added to CISA KEV catalog as of ${dateAdded}`;
    }
    return [change];
  }
  if (newField === undefined) {
    return [{ op: 'remove', path: 'kev', oldValue: oldField }];
  }
  if (typeof oldField !== 'object' || typeof newField !== 'object' || oldField === null || newField === null) {
    if (JSON.stringify(oldField) === JSON.stringify(newField)) return [];
    return [{ op: 'replace', path: 'kev', oldValue: oldField, newValue: newField }];
  }
  const oldObj = oldField as Record<string, unknown>;
  const newObj = newField as Record<string, unknown>;
  const changes: FieldChange[] = [];
  const allKeys = new Set([...Object.keys(oldObj), ...Object.keys(newObj)]);
  for (const key of allKeys) {
    const o = oldObj[key];
    const n = newObj[key];
    if (JSON.stringify(o) === JSON.stringify(n)) continue;
    let change: FieldChange;
    if (o === undefined) {
      change = { op: 'add', path: `kev.${key}`, newValue: n };
    } else if (n === undefined) {
      change = { op: 'remove', path: `kev.${key}`, oldValue: o };
    } else {
      change = { op: 'replace', path: `kev.${key}`, oldValue: o, newValue: n };
    }
    // Annotate the significant false→true inKev flip
    if (key === 'inKev' && o === false && n === true) {
      const dateAdded = typeof newObj['dateAdded'] === 'string' ? newObj['dateAdded'] : 'unknown date';
      change.message = `Newly added to CISA KEV catalog as of ${dateAdded}`;
    }
    changes.push(change);
  }
  return changes;
}

/** Diff the `cwe[]` field as a set — order does not matter. */
function diffCweSet(oldField: unknown, newField: unknown): FieldChange[] {
  const toSet = (v: unknown): Set<string> => {
    if (!Array.isArray(v)) return new Set();
    return new Set(v.filter((x): x is string => typeof x === 'string'));
  };
  const oldSet = toSet(oldField);
  const newSet = toSet(newField);
  if (oldSet.size === 0 && newSet.size === 0) return [];
  const changes: FieldChange[] = [];
  for (const c of newSet) {
    if (!oldSet.has(c)) changes.push({ op: 'add', path: 'cwe', newValue: c });
  }
  for (const c of oldSet) {
    if (!newSet.has(c)) changes.push({ op: 'remove', path: 'cwe', oldValue: c });
  }
  return changes;
}

interface AffectedPackage {
  name?: string;
  version?: string;
  cpe?: string;
  purl?: string;
  fixedInVersion?: string;
  [key: string]: unknown;
}

/** Build the natural key for an AffectedPackage: `name@version`. */
function packageKey(pkg: AffectedPackage): string | null {
  const name = pkg?.name;
  const version = pkg?.version;
  if (typeof name !== 'string' || name.length === 0) return null;
  if (typeof version !== 'string' || version.length === 0) return null;
  return `${name}@${version}`;
}

/**
 * Diff a single pair of affectedPackages entries (matched by name+version).
 * Emits per-field changes for cpe / purl / fixedInVersion and any other
 * non-key fields that differ.
 */
function diffAffectedPackageEntry(
  key: string,
  oldPkg: AffectedPackage,
  newPkg: AffectedPackage,
): FieldChange[] {
  const changes: FieldChange[] = [];
  const allKeys = new Set([...Object.keys(oldPkg), ...Object.keys(newPkg)]);
  for (const k of allKeys) {
    if (k === 'name' || k === 'version') continue; // part of the match key
    const o = oldPkg[k];
    const n = newPkg[k];
    if (JSON.stringify(o) === JSON.stringify(n)) continue;
    if (o === undefined) {
      changes.push({ op: 'add', path: `affectedPackages[${key}].${k}`, newValue: n });
    } else if (n === undefined) {
      changes.push({ op: 'remove', path: `affectedPackages[${key}].${k}`, oldValue: o });
    } else {
      changes.push({
        op: 'replace', path: `affectedPackages[${key}].${k}`, oldValue: o, newValue: n,
      });
    }
  }
  return changes;
}

/**
 * Diff old vs new affectedPackages[] arrays. Entries are matched by the
 * `name@version` tuple; added/removed packages emit whole-entry records;
 * matched pairs are decomposed via diffAffectedPackageEntry.
 */
function diffAffectedPackages(oldField: unknown, newField: unknown): FieldChange[] {
  const oldArr = Array.isArray(oldField) ? (oldField as AffectedPackage[]) : [];
  const newArr = Array.isArray(newField) ? (newField as AffectedPackage[]) : [];
  if (oldArr.length === 0 && newArr.length === 0) return [];

  const oldByKey = new Map<string, AffectedPackage>();
  for (const p of oldArr) {
    const k = packageKey(p);
    if (k) oldByKey.set(k, p);
  }
  const newByKey = new Map<string, AffectedPackage>();
  for (const p of newArr) {
    const k = packageKey(p);
    if (k) newByKey.set(k, p);
  }

  const changes: FieldChange[] = [];
  const allKeys = new Set([...oldByKey.keys(), ...newByKey.keys()]);
  for (const key of allKeys) {
    const o = oldByKey.get(key);
    const n = newByKey.get(key);
    if (o && !n) {
      changes.push({ op: 'remove', path: `affectedPackages[${key}]`, oldValue: o });
    } else if (!o && n) {
      changes.push({ op: 'add', path: `affectedPackages[${key}]`, newValue: n });
    } else if (o && n) {
      changes.push(...diffAffectedPackageEntry(key, o, n));
    }
  }
  return changes;
}

/**
 * Detect whether a document is a baseline (not results).
 * Baselines have `requirements` at the top level and lack `baselines`, `targets`, and `statistics`.
 */
function isBaselineDocument(doc: Record<string, unknown>): boolean {
  return (
    Array.isArray(doc['requirements']) &&
    !Array.isArray(doc['baselines']) &&
    !Array.isArray(doc['targets']) &&
    doc['statistics'] === undefined
  );
}

/** Default tracked fields for baseline evolution comparisons. */
const BASELINE_TRACKED_FIELDS = ['title', 'impact', 'descriptions', 'tags'];

/**
 * Compare two HDF baseline documents and produce a structured comparison
 * showing requirement changes between baseline versions.
 *
 * Unlike diffHdf (which compares results/evaluations), this compares baseline
 * definitions — requirements without results. There is no status-based classification
 * (fixed/regressed); only metadata changes (title, impact, descriptions, tags) are tracked.
 */
export function diffBaselines(
  oldBaseline: Record<string, unknown>,
  newBaseline: Record<string, unknown>,
  options?: DiffOptions,
): HdfComparison {
  const trackedFields = options?.trackedFields ?? BASELINE_TRACKED_FIELDS;
  const matchOpts = buildMatchOptions(options);

  // Extract requirements from baseline documents
  const oldReqs = (oldBaseline['requirements'] as RequirementLike[] | undefined) ?? [];
  const newReqs = (newBaseline['requirements'] as RequirementLike[] | undefined) ?? [];

  // Use the matching system to pair requirements
  const matchResult = matchRequirements(
    oldReqs as unknown as Record<string, unknown>[],
    newReqs as unknown as Record<string, unknown>[],
    matchOpts,
  );

  // Build requirement diffs from match results
  const requirementDiffs: RequirementDiff[] = [];

  // Matched pairs
  for (const pair of matchResult.matched) {
    const oldReq = pair.oldReq as RequirementLike;
    const newReq = pair.newReq as RequirementLike;
    const id = (newReq.id ?? oldReq.id) as string;

    const fieldChanges = computeFieldChanges(oldReq, newReq, trackedFields);

    // For baseline evolution, state is determined by metadata changes only
    const state: 'unchanged' | 'updated' = fieldChanges.length > 0 ? 'updated' : 'unchanged';

    // Determine change reasons for baseline evolution
    const changeReasons: Array<'impactChanged' | 'metadataChanged'> = [];
    if (oldReq.impact !== newReq.impact) {
      changeReasons.push('impactChanged');
    }
    const oldTags = JSON.stringify(oldReq['tags'] ?? {});
    const newTags = JSON.stringify(newReq['tags'] ?? {});
    const oldDescs = JSON.stringify(oldReq['descriptions'] ?? []);
    const newDescs = JSON.stringify(newReq['descriptions'] ?? []);
    const oldTitle = oldReq['title'] as string | undefined;
    const newTitle = newReq['title'] as string | undefined;
    if (oldTags !== newTags || oldDescs !== newDescs || oldTitle !== newTitle) {
      changeReasons.push('metadataChanged');
    }

    requirementDiffs.push({
      id,
      title: newReq.title ?? oldReq.title,
      state,
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
    requirementDiffs.push({
      id: oldReq.id,
      title: oldReq.title,
      state: 'absent',
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
    requirementDiffs.push({
      id: newReq.id,
      title: newReq.title,
      state: 'new',
      changeReasons: [],
      newImpact: newReq.impact,
      fieldChanges: [],
      before: null,
      after: newReq as unknown as Record<string, unknown>,
    });
  }

  // Sort by id
  requirementDiffs.sort((a, b) => a.id.localeCompare(b.id));

  // Build baseline diff from top-level baseline metadata
  const oldName = oldBaseline['name'] as string | undefined ?? '';
  const newName = newBaseline['name'] as string | undefined ?? '';
  const oldVersion = oldBaseline['version'] as string | undefined;
  const newVersion = newBaseline['version'] as string | undefined;

  const baselineDiffs: BaselineDiff[] = [];
  const baselineName = newName || oldName;
  if (baselineName) {
    const versionChanged = oldVersion !== newVersion;
    baselineDiffs.push({
      name: baselineName,
      oldVersion,
      newVersion,
      state: versionChanged ? 'updated' : 'unchanged',
    });
  }

  // Build sources
  const sources: Source[] = [
    { role: 'old', label: oldVersion ? `${baselineName} ${oldVersion}` : baselineName || 'Old baseline' },
    { role: 'new', label: newVersion ? `${baselineName} ${newVersion}` : baselineName || 'New baseline' },
  ];

  const comparison: HdfComparison = {
    formatVersion: '1.0.0',
    comparisonMode: 'baselineEvolution',
    timestamp: new Date().toISOString(),
    sources,
    matching: {
      primaryStrategy: resolveStrategyName(options),
    },
    summary: computeSummary(requirementDiffs),
    baselineDiffs,
    requirementDiffs,
  };

  if (options?.validateOutput) {
    const result = validateComparison(comparison);
    /* c8 ignore start */
    if (!result.valid) {
      throw new Error(`Output validation failed: ${result.errors?.join(', ')}`);
    }
    /* c8 ignore stop */
  }

  return comparison;
}

/**
 * Detect whether a document is a system document (has components[] but no baselines/requirements).
 */
function isSystemDocument(doc: Record<string, unknown>): boolean {
  return (
    Array.isArray(doc['components']) &&
    !Array.isArray(doc['baselines']) &&
    !Array.isArray(doc['requirements']) &&
    doc['statistics'] === undefined
  );
}

/** Fields tracked for system-level field changes. */
const SYSTEM_TOP_LEVEL_FIELDS = ['authorizationStatus', 'categorizationLevel', 'description'];

/** Fields tracked for component-level field changes. */
const COMPONENT_TRACKED_FIELDS = [
  'type', 'description', 'baselineRefs', 'inputOverrides', 'sbomRef', 'targetSelector',
];

/**
 * Compare two HDF system documents and produce a structured comparison
 * showing component-level changes between system versions.
 *
 * Components are matched by componentId (UUID) when available, falling back
 * to exact name matching. Top-level system fields, data flows, and embedded
 * SBOMs are also compared.
 */
export function diffSystems(
  oldSystem: Record<string, unknown>,
  newSystem: Record<string, unknown>,
  options?: DiffOptions,
): HdfComparison {
  const oldComponents = (oldSystem['components'] as Record<string, unknown>[] | undefined) ?? [];
  const newComponents = (newSystem['components'] as Record<string, unknown>[] | undefined) ?? [];

  // Match components: prefer componentId, fall back to name
  const pairs = matchComponents(oldComponents, newComponents);
  const componentDiffs: ComponentDiff[] = [];

  for (const { oldComp, newComp, name } of pairs) {
    if (oldComp && newComp) {
      const fieldChanges = computeComponentFieldChanges(oldComp, newComp, COMPONENT_TRACKED_FIELDS);
      const state = fieldChanges.length > 0 ? 'updated' : 'unchanged';
      componentDiffs.push({ name, state, before: oldComp, after: newComp, fieldChanges });
    } else if (oldComp && !newComp) {
      componentDiffs.push({ name, state: 'absent', before: oldComp, after: null, fieldChanges: [] });
    } else if (!oldComp && newComp) {
      componentDiffs.push({ name, state: 'new', before: null, after: newComp, fieldChanges: [] });
    }
  }

  componentDiffs.sort((a, b) => a.name.localeCompare(b.name));

  // Compare top-level system fields
  const systemFieldChanges = computeComponentFieldChanges(
    oldSystem, newSystem, SYSTEM_TOP_LEVEL_FIELDS,
  );

  // Build summary counts based on component diffs
  const counts = { new: 0, absent: 0, unchanged: 0, updated: 0 };
  for (const cd of componentDiffs) {
    counts[cd.state]++;
  }

  const oldName = oldSystem['name'] as string | undefined ?? '';
  const newName = newSystem['name'] as string | undefined ?? '';
  const systemName = newName || oldName;

  const sources: Source[] = [
    { role: 'old', label: systemName ? `${systemName} (old)` : 'Old system' },
    { role: 'new', label: systemName ? `${systemName} (new)` : 'New system' },
  ];

  const comparison: HdfComparison = {
    formatVersion: '1.0.0',
    comparisonMode: 'systemDrift',
    timestamp: new Date().toISOString(),
    sources,
    summary: {
      total: pairs.length,
      matchedCount: counts.unchanged + counts.updated,
      unmatchedOldCount: counts.absent,
      unmatchedNewCount: counts.new,
      new: counts.new,
      absent: counts.absent,
      unchanged: counts.unchanged,
      updated: counts.updated,
      fixed: 0,
      regressed: 0,
    },
    baselineDiffs: [],
    requirementDiffs: [],
    componentDiffs,
  };

  // Extensions: system field changes + data flow changes
  const extensions: Record<string, unknown> = {};
  if (systemFieldChanges.length > 0) {
    extensions['systemFieldChanges'] = systemFieldChanges;
  }
  const dataFlowChanges = diffDataFlows(oldSystem, newSystem);
  if (dataFlowChanges.length > 0) {
    extensions['dataFlowChanges'] = dataFlowChanges;
  }
  if (Object.keys(extensions).length > 0) {
    comparison.extensions = extensions;
  }

  // Diff embedded SBOMs across matched components
  const allPackageDiffs = diffEmbeddedSboms(pairs);
  if (allPackageDiffs.length > 0) {
    comparison.packageDiffs = allPackageDiffs;
  }

  if (options?.validateOutput) {
    const result = validateComparison(comparison);
    /* c8 ignore start */
    if (!result.valid) {
      throw new Error(`Output validation failed: ${result.errors?.join(', ')}`);
    }
    /* c8 ignore stop */
  }

  return comparison;
}

interface ComponentPair {
  name: string;
  oldComp: Record<string, unknown> | undefined;
  newComp: Record<string, unknown> | undefined;
}

/**
 * Match old and new components by componentId (when available) or name.
 */
function matchComponents(
  oldComponents: Record<string, unknown>[],
  newComponents: Record<string, unknown>[],
): ComponentPair[] {
  const matched = new Set<number>(); // indices of matched new components
  const pairs: ComponentPair[] = [];

  // First pass: match by componentId
  const newById = new Map<string, number>();
  for (let i = 0; i < newComponents.length; i++) {
    const id = newComponents[i]!['componentId'] as string | undefined;
    if (id) newById.set(id, i);
  }

  const oldMatched = new Set<number>();
  for (let i = 0; i < oldComponents.length; i++) {
    const oldId = oldComponents[i]!['componentId'] as string | undefined;
    if (oldId && newById.has(oldId)) {
      const ni = newById.get(oldId)!;
      const newComp = newComponents[ni]!;
      pairs.push({
        name: (newComp['name'] as string) || (oldComponents[i]!['name'] as string) || oldId,
        oldComp: oldComponents[i],
        newComp,
      });
      matched.add(ni);
      oldMatched.add(i);
    }
  }

  // Second pass: match remaining by name
  const newByName = new Map<string, number>();
  for (let i = 0; i < newComponents.length; i++) {
    if (matched.has(i)) continue;
    const name = newComponents[i]!['name'] as string;
    if (name) newByName.set(name, i);
  }

  for (let i = 0; i < oldComponents.length; i++) {
    if (oldMatched.has(i)) continue;
    const name = oldComponents[i]!['name'] as string;
    if (name && newByName.has(name)) {
      const ni = newByName.get(name)!;
      pairs.push({ name, oldComp: oldComponents[i], newComp: newComponents[ni] });
      matched.add(ni);
      oldMatched.add(i);
      newByName.delete(name);
    }
  }

  // Unmatched old → absent
  for (let i = 0; i < oldComponents.length; i++) {
    if (oldMatched.has(i)) continue;
    const name = (oldComponents[i]!['name'] as string) || `component-${i}`;
    pairs.push({ name, oldComp: oldComponents[i], newComp: undefined });
  }

  // Unmatched new → new
  for (let i = 0; i < newComponents.length; i++) {
    if (matched.has(i)) continue;
    const name = (newComponents[i]!['name'] as string) || `component-${i}`;
    pairs.push({ name, oldComp: undefined, newComp: newComponents[i] });
  }

  return pairs;
}

/**
 * Diff data flows between two system documents. Flows are keyed by from+to.
 */
function diffDataFlows(
  oldSystem: Record<string, unknown>,
  newSystem: Record<string, unknown>,
): Array<{ state: string; flow: Record<string, unknown> }> {
  const oldFlows = (oldSystem['dataFlows'] as Record<string, unknown>[] | undefined) ?? [];
  const newFlows = (newSystem['dataFlows'] as Record<string, unknown>[] | undefined) ?? [];

  if (oldFlows.length === 0 && newFlows.length === 0) return [];

  const flowKey = (f: Record<string, unknown>): string => {
    const from = f['from'] as string ?? '';
    const to = typeof f['to'] === 'string' ? f['to'] as string : JSON.stringify(f['to']);
    return `${from}→${to}`;
  };

  const oldMap = new Map<string, Record<string, unknown>>();
  for (const f of oldFlows) oldMap.set(flowKey(f), f);
  const newMap = new Map<string, Record<string, unknown>>();
  for (const f of newFlows) newMap.set(flowKey(f), f);

  const allKeys = new Set([...oldMap.keys(), ...newMap.keys()]);
  const changes: Array<{ state: string; flow: Record<string, unknown> }> = [];

  for (const key of allKeys) {
    const oldF = oldMap.get(key);
    const newF = newMap.get(key);
    if (oldF && newF) {
      if (JSON.stringify(oldF) !== JSON.stringify(newF)) {
        changes.push({ state: 'updated', flow: newF });
      }
    } else if (oldF && !newF) {
      changes.push({ state: 'removed', flow: oldF });
    } else if (!oldF && newF) {
      changes.push({ state: 'added', flow: newF });
    }
  }

  return changes;
}

/**
 * Diff embedded SBOMs across matched component pairs.
 */
function diffEmbeddedSboms(pairs: ComponentPair[]): PackageDiff[] {
  const allDiffs: PackageDiff[] = [];

  for (const { oldComp, newComp } of pairs) {
    if (!oldComp || !newComp) continue;
    const oldSbom = oldComp['sbom'];
    const newSbom = newComp['sbom'];
    if (!oldSbom || !newSbom) continue;
    if (typeof oldSbom !== 'object' || typeof newSbom !== 'object') continue;

    try {
      const result = diffSboms(JSON.stringify(oldSbom), JSON.stringify(newSbom));
      allDiffs.push(...result.packageDiffs);
    } catch {
      // Skip SBOM diff if formats are incompatible
    }
  }

  return allDiffs;
}

/**
 * Compute field-level changes for component or system fields.
 * Uses JSON Patch-like op/path format.
 */
function computeComponentFieldChanges(
  oldObj: Record<string, unknown>,
  newObj: Record<string, unknown>,
  trackedFields: string[],
): FieldChange[] {
  const changes: FieldChange[] = [];

  for (const field of trackedFields) {
    const oldVal = oldObj[field];
    const newVal = newObj[field];

    if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
      if (oldVal === undefined && newVal !== undefined) {
        changes.push({ op: 'add', path: field, newValue: newVal });
      } else if (oldVal !== undefined && newVal === undefined) {
        changes.push({ op: 'remove', path: field, oldValue: oldVal });
      } else {
        changes.push({ op: 'replace', path: field, oldValue: oldVal, newValue: newVal });
      }
    }
  }

  return changes;
}
