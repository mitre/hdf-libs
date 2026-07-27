import { sha256 } from '@mitre/hdf-utilities';
import {
  dedupEvents,
  groupEventChains,
  verifyEventChain,
} from './event-stream-common.js';

/**
 * Caller-supplied identity for a reassembly run. Everything else in the
 * derivation block is computed from the seed text and the event batch — no
 * wall clock, no RNG. Go parity: ApplyInputs in hdf-diff/go/apply_events.go.
 */
export interface ApplyInputs {
  /** Names the reconciling tool — a reconciled document never masquerades as scanner output. */
  generator: { name: string; version: string };
  /** Locates the seed snapshot; its checksum is computed from the seed text. */
  seedUri: string;
  /** The event-stream producer context recorded in the derivation block. */
  source: string;
}

/**
 * A non-fatal per-key anomaly. Warnings never abort the fold: the key is
 * still applied last-value-wins and the warning marks it unverified
 * (ADR-0005 §4 fold contract).
 */
export interface ApplyWarning {
  requirementId: string;
  /** chainGap | newOnExisting | absentUnknown | multiBaseline */
  kind: string;
  message: string;
}

export interface ApplyResult {
  results: Record<string, unknown>;
  warnings: ApplyWarning[];
}

type Doc = Record<string, unknown>;

function findRequirement(
  doc: Doc,
  id: string,
): { baseline: Doc; requirements: Doc[]; index: number } | null {
  const baselines = (doc['baselines'] as Doc[] | undefined) ?? [];
  for (const baseline of baselines) {
    const requirements = (baseline['requirements'] as Doc[] | undefined) ?? [];
    const index = requirements.findIndex((r) => r['id'] === id);
    if (index >= 0) {
      return { baseline, requirements, index };
    }
  }
  return null;
}

/**
 * Reassemble the current posture from a seed hdf-results document plus a
 * batch of requirement-change events (ADR-0005 §§4-7): keyed last-value-wins
 * by sequence, idempotent via (source, eventId) dedup, tombstone-aware
 * (absent removes), total over the event-state enum. Delivery order and
 * duplicates never change the output. The result carries the caller's
 * generator and a derivation block (seed pinned by content, watermark,
 * count, asOf) so it can never masquerade as scan evidence. Chain gaps and
 * anomalies surface as warnings, never as refusal. Go parity:
 * ApplyChangeEvents.
 */
export async function applyChangeEvents(
  seedJson: string,
  events: Doc[],
  inputs: ApplyInputs,
): Promise<ApplyResult> {
  const doc = JSON.parse(seedJson) as Doc;
  const seedChecksum = await sha256(seedJson);
  const docTimestamp = (doc['timestamp'] as string | undefined) ?? '';

  const { byKey, keys } = groupEventChains(dedupEvents(events));

  const warnings: ApplyWarning[] = [];
  let maxSequence = 0;
  let maxOccurredMs = Number.NEGATIVE_INFINITY;
  let asOfFromEvents = '';
  let eventsApplied = 0;
  const insertions: { sequence: number; id: string; payload: Doc }[] = [];

  for (const id of keys) {
    const chain = byKey.get(id) ?? [];
    const first = chain[0];
    const winner = chain[chain.length - 1];
    if (!first || !winner) continue;
    const inSeed = findRequirement(doc, id) !== null;

    // One warning per key, application anomalies taking priority over
    // chain-link mismatches.
    let keyWarned = false;
    const keyWarn = (kind: string, message: string): void => {
      if (!keyWarned) {
        keyWarned = true;
        warnings.push({ requirementId: id, kind, message });
      }
    };

    // Chain verification (shared with the fold): unanchored chains defer
    // to the application outcome below.
    const located = findRequirement(doc, id);
    await verifyEventChain(chain, located ? (located.requirements[located.index] ?? null) : null, inSeed, keyWarn);
    const verifyLinks = inSeed || first['state'] === 'new';

    // Apply the winner.
    const winnerSeq = winner['sequence'] as number;
    if (winnerSeq > maxSequence) maxSequence = winnerSeq;
    const occurredMs = new Date(winner['timestamp'] as string).getTime();
    if (occurredMs > maxOccurredMs) {
      maxOccurredMs = occurredMs;
      asOfFromEvents = winner['timestamp'] as string;
    }

    if (winner['state'] === 'absent') {
      const hit = findRequirement(doc, id);
      if (hit) {
        hit.requirements.splice(hit.index, 1);
        eventsApplied++;
      } else {
        keyWarn('absentUnknown', 'absent event for a key not present in the document');
      }
      continue;
    }

    if (!verifyLinks) {
      keyWarn('chainGap', 'non-new chain for a key the seed does not carry');
    }

    const payload = winner['after'] as Doc | null;
    if (!payload) {
      keyWarn('chainGap', 'winning event carries no applicable after payload');
      continue;
    }
    const hit = findRequirement(doc, id);
    if (hit) {
      hit.requirements[hit.index] = structuredClone(payload);
      eventsApplied++;
    } else {
      insertions.push({ sequence: winnerSeq, id, payload: structuredClone(payload) });
    }
  }

  // Deterministic insertion order regardless of delivery order.
  insertions.sort((a, b) => (a.sequence !== b.sequence ? a.sequence - b.sequence : a.id.localeCompare(b.id)));
  if (insertions.length > 0) {
    const baselines = (doc['baselines'] as Doc[] | undefined) ?? [];
    const firstBaseline = baselines[0];
    const firstInsertion = insertions[0];
    if (!firstBaseline || !firstInsertion) {
      throw new Error('seed document has no baselines to insert new requirements into');
    }
    if (baselines.length > 1) {
      warnings.push({
        requirementId: firstInsertion.id,
        kind: 'multiBaseline',
        message: 'seed has multiple baselines; new requirements appended to the first',
      });
    }
    const requirements = (firstBaseline['requirements'] as Doc[] | undefined) ?? [];
    for (const ins of insertions) {
      requirements.push(ins.payload);
      eventsApplied++;
    }
    firstBaseline['requirements'] = requirements;
  }

  const asOf = asOfFromEvents !== '' ? asOfFromEvents : docTimestamp;
  if (asOf === '') {
    throw new Error('cannot derive asOf: no events supplied and the seed document has no timestamp');
  }

  doc['generator'] = { name: inputs.generator.name, version: inputs.generator.version };
  doc['timestamp'] = asOf;
  doc['derivation'] = {
    seed: {
      uri: inputs.seedUri,
      checksum: { algorithm: 'sha256', value: seedChecksum },
    },
    source: inputs.source,
    throughSequence: maxSequence,
    eventsApplied,
    asOf,
  };

  return { results: doc, warnings };
}
