import { formatTimestamp, parseTimestamp } from '@mitre/hdf-utilities';
import { computeSummary } from './summary.js';
import { computeEffectiveStatus } from './status.js';
import { computeFieldChanges, extractDrift, DEFAULT_TRACKED_FIELDS } from './diff.js';
import { dedupEvents, groupEventChains, verifyEventChain } from './event-stream-common.js';
import type { ApplyWarning } from './apply-events.js';
import type { RequirementDiff, ChangeReason, RequirementState } from './types.js';

type Doc = Record<string, unknown>;
type FieldChangesInput = Parameters<typeof computeFieldChanges>[0];

export interface FoldResult {
  comparison: Record<string, unknown>;
  warnings: ApplyWarning[];
}

function findSeedRequirement(doc: Doc, id: string): Doc | null {
  const baselines = (doc['baselines'] as Doc[] | undefined) ?? [];
  for (const baseline of baselines) {
    const requirements = (baseline['requirements'] as Doc[] | undefined) ?? [];
    const hit = requirements.find((r) => r['id'] === id);
    if (hit) return hit;
  }
  return null;
}

/**
 * Materialize a change-event batch into a full systemDrift hdf-comparison
 * against the seed document (ADR-0005 §5): each winning event lifts into the
 * Requirement_Diff shape the batch engine produces — before from the seed,
 * after from the event payload, field changes derived by the batch engine's
 * own computeFieldChanges — under the same fold contract as
 * applyChangeEvents (dedup, last-value-wins by sequence, tombstone-aware,
 * warnings never abort). Deterministic: the comparison timestamp is the
 * latest event occurrence, and seed-side override expiry anchors to the
 * seed's own timestamp (falling back to the event occurrence when the seed
 * has none) — never wall clock. Go parity: FoldChangeEventsIntoComparison.
 */
export async function foldChangeEventsIntoComparison(
  seedJson: string,
  events: Doc[],
): Promise<FoldResult> {
  const doc = JSON.parse(seedJson) as Doc;
  const docTimestamp = (doc['timestamp'] as string | undefined) ?? '';

  const { byKey, keys } = groupEventChains(dedupEvents(events));

  const warnings: ApplyWarning[] = [];
  const diffs: RequirementDiff[] = [];
  let maxOccurredMs = Number.NEGATIVE_INFINITY;
  let asOfFromEvents = '';
  let systemRef = '';

  for (const id of keys) {
    const chain = byKey.get(id) ?? [];
    const winner = chain[chain.length - 1];
    if (!winner) continue;
    if (systemRef === '') {
      systemRef = (winner['systemRef'] as string | undefined) ?? '';
    }

    let keyWarned = false;
    const keyWarn = (kind: string, message: string): void => {
      if (!keyWarned) {
        keyWarned = true;
        warnings.push({ requirementId: id, kind, message });
      }
    };

    const seedReq = findSeedRequirement(doc, id);
    const inSeed = seedReq !== null;
    await verifyEventChain(chain, seedReq, inSeed, keyWarn);

    // parseTimestamp + formatTimestamp keep the occurrence host-independent
    // and render timestamps as trimmed UTC, matching the Go peer's
    // winner.Timestamp.UTC().Format(RFC3339Nano).
    const occurred = parseTimestamp(winner['timestamp'] as string);
    if (occurred !== null && occurred.getTime() > maxOccurredMs) {
      maxOccurredMs = occurred.getTime();
      asOfFromEvents = formatTimestamp(occurred);
    }
    const newTs = occurred !== null ? formatTimestamp(occurred) : (winner['timestamp'] as string);
    // Seed-side override expiry needs a deterministic anchor: the seed's
    // own observation time, else the event occurrence — a timestamp-less
    // seed must never fall through to the wall clock.
    const seedRef = docTimestamp !== '' ? docTimestamp : newTs;

    if (winner['state'] === 'absent') {
      if (!seedReq) {
        keyWarn('absentUnknown', 'absent event for a key not present in the seed');
        continue;
      }
      diffs.push({
        id,
        title: seedReq['title'] as string | undefined,
        state: 'absent',
        oldEffectiveStatus: computeEffectiveStatus(seedReq, seedRef),
        changeReasons: [],
        oldImpact: seedReq['impact'] as number | undefined,
        fieldChanges: [],
        before: seedReq,
        after: null,
      });
      continue;
    }

    const after = winner['after'] as Doc | null;
    if (!after) {
      keyWarn('chainGap', 'winning event carries no applicable after payload');
      continue;
    }
    const newStatus = computeEffectiveStatus(after, newTs);

    // Content-bearing chain for a key the seed does not carry: the
    // comparison vocabulary allows a null before only on new, so the entry
    // is coerced to the batch engine's new shape; the warning records the
    // anomaly.
    if (!seedReq) {
      if (winner['state'] !== 'new') {
        keyWarn('chainGap', 'non-new chain for a key the seed does not carry; lifted as new');
      }
      diffs.push({
        id,
        title: after['title'] as string | undefined,
        state: 'new',
        newEffectiveStatus: newStatus,
        changeReasons: [],
        newImpact: after['impact'] as number | undefined,
        fieldChanges: [],
        before: null,
        after,
      });
      continue;
    }

    diffs.push({
      id,
      title: (after['title'] as string | undefined) ?? (seedReq['title'] as string | undefined),
      state: winner['state'] as RequirementState,
      oldEffectiveStatus: computeEffectiveStatus(seedReq, seedRef),
      newEffectiveStatus: newStatus,
      changeReasons: ((winner['changeReasons'] as string[] | undefined) ?? []) as ChangeReason[],
      oldImpact: seedReq['impact'] as number | undefined,
      newImpact: after['impact'] as number | undefined,
      fieldChanges: computeFieldChanges(
        seedReq as FieldChangesInput,
        after as FieldChangesInput,
        DEFAULT_TRACKED_FIELDS,
      ),
      before: seedReq,
      after,
    });
  }

  diffs.sort((a, b) => a.id.localeCompare(b.id));

  const asOf = asOfFromEvents !== '' ? asOfFromEvents : docTimestamp;
  if (asOf === '') {
    throw new Error(
      'cannot derive a comparison timestamp: no events supplied and the seed document has no timestamp',
    );
  }

  return {
    comparison: {
      formatVersion: '1.0.0',
      comparisonMode: 'systemDrift',
      timestamp: asOf,
      ...(systemRef !== '' ? { systemRef } : {}),
      sources: [
        { role: 'old', label: 'Old evaluation' },
        { role: 'new', label: 'New evaluation' },
      ],
      matching: { primaryStrategy: 'exactId' },
      summary: computeSummary(diffs),
      baselineDiffs: [],
      requirementDiffs: diffs,
      drift: extractDrift(diffs),
    },
    warnings,
  };
}
