import { compareCodePoint, formatTimestamp, parseTimestamp, sha256 } from '@mitre/hdf-utilities';
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
  /**
   * Names the reconciling tool — a reconciled document never masquerades as scanner
   * output.
   */
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

interface RequirementSite {
  baseline: Doc;
  indexes: number[];
}

/**
 * Every place an id's entries sit, across all baselines. An id names the requirement
 * rather than the finding, so it may occupy several positions and an event carries all
 * of them; placing one payload on the first hit overwrote a real entry's content. Peer
 * of the Go findRequirementSites.
 */
function findRequirementSites(doc: Doc, id: string): RequirementSite[] {
  const sites: RequirementSite[] = [];
  const baselines = (doc['baselines'] as Doc[] | undefined) ?? [];
  for (const baseline of baselines) {
    const requirements = (baseline['requirements'] as Doc[] | undefined) ?? [];
    const indexes = requirements.flatMap((r, i) => (r['id'] === id ? [i] : []));
    if (indexes.length > 0) {
      sites.push({ baseline, indexes });
    }
  }
  return sites;
}

/** How many entries the id holds across every site. */
function siteEntryCount(sites: readonly RequirementSite[]): number {
  return sites.reduce((total, site) => total + site.indexes.length, 0);
}

/**
 * Splits an event's entries across the sites the id occupies, one share each. The shares
 * match the seed's own counts when the number agrees; otherwise the arrangement is
 * undecidable and the first site takes everything, which the caller reports.
 */
function payloadShares(sites: readonly RequirementSite[], payload: readonly Doc[]): Doc[][] {
  const shares: Doc[][] = sites.map(() => []);
  if (siteEntryCount(sites) !== payload.length) {
    shares[0] = [...payload];
    return shares;
  }
  let offset = 0;
  for (const [i, site] of sites.entries()) {
    shares[i] = payload.slice(offset, offset + site.indexes.length);
    offset += site.indexes.length;
  }
  return shares;
}

/**
 * Writes an event's entries over the id's existing entries, because the event's list is
 * the whole truth about that id. Both the event's after[] and the sites are in document
 * order, so when the event carries as many entries as the seed holds each site takes
 * its own share and the seed's arrangement across baselines is reproduced exactly. An
 * empty payload removes them all, which is what absent means.
 */
function placeEntries(sites: readonly RequirementSite[], payload: readonly Doc[]): void {
  const shares = payloadShares(sites, payload);
  for (const [i, site] of sites.entries()) {
    const requirements = (site.baseline['requirements'] as Doc[] | undefined) ?? [];
    const drop = new Set(site.indexes);
    const kept: Doc[] = [];
    let written = false;
    for (const [j, requirement] of requirements.entries()) {
      if (!drop.has(j)) {
        kept.push(requirement);
        continue;
      }
      if (!written) {
        kept.push(...(shares[i] ?? []));
        written = true;
      }
    }
    site.baseline['requirements'] = kept;
  }
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
    const inSeed = findRequirementSites(doc, id).length > 0;

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
    const sites = findRequirementSites(doc, id);
    const seedEntries = sites.flatMap((site) => {
      const reqs = (site.baseline['requirements'] as Doc[] | undefined) ?? [];
      return site.indexes.flatMap((i) => (reqs[i] ? [reqs[i]] : []));
    }) as Doc[];
    await verifyEventChain(chain, seedEntries, inSeed, keyWarn);
    const verifyLinks = inSeed || first['state'] === 'new';

    // Apply the winner.
    const winnerSeq = winner['sequence'] as number;
    if (winnerSeq > maxSequence) maxSequence = winnerSeq;
    // parseTimestamp + formatTimestamp keep the occurrence host-independent
    // and render asOf as trimmed UTC, matching the Go peer's
    // winner.Timestamp.UTC().Format(RFC3339Nano).
    const occurred = parseTimestamp(winner['timestamp'] as string);
    if (occurred !== null && occurred.getTime() > maxOccurredMs) {
      maxOccurredMs = occurred.getTime();
      asOfFromEvents = formatTimestamp(occurred);
    }

    if (winner['state'] === 'absent') {
      // The requirement left the assessment, so EVERY entry it carried goes: removing one
      // of several left the rest behind as a requirement that had supposedly disappeared.
      if (sites.length === 0) {
        keyWarn('absentUnknown', 'absent event for a key not present in the document');
        continue;
      }
      placeEntries(sites, []);
      eventsApplied++;
      continue;
    }

    if (!verifyLinks) {
      keyWarn('chainGap', 'non-new chain for a key the seed does not carry');
    }

    const payload = winner['after'] as Doc[] | null;
    if (!payload || payload.length === 0) {
      keyWarn('chainGap', 'winning event carries no applicable after payload');
      continue;
    }
    if (sites.length === 0) {
      for (const entry of payload) {
        insertions.push({ sequence: winnerSeq, id, payload: structuredClone(entry) });
      }
      continue;
    }
    // The event carries every entry of the id, so they replace every entry of the id. Only
    // a change in their NUMBER leaves the arrangement undecidable, because the event cannot
    // then say which belongs where; that case is reported, not done silently.
    if (siteEntryCount(sites) !== payload.length) {
      keyWarn(
        'occurrenceMismatch',
        'the event carries a different number of this id\'s entries than the seed; ' +
          'they are replaced in the first baseline that carries it',
      );
    }
    placeEntries(sites, payload.map((entry) => structuredClone(entry)));
    eventsApplied++
  }

  // Deterministic insertion order regardless of delivery order.
  insertions.sort((a, b) => (a.sequence !== b.sequence ? a.sequence - b.sequence : compareCodePoint(a.id, b.id)));
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
