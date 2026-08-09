import { computeEffectiveChecksum } from './effective-checksum.js';

type Doc = Record<string, unknown>;

/** Extract the priorChecksum hex from an event ('' when null/absent). */
export function eventPriorValue(ev: Doc): string {
  const prior = ev['priorChecksum'] as { value?: string } | null | undefined;
  return prior?.value ?? '';
}

/** Effective checksum of a requirement ('' when absent). */
export async function requirementChecksum(req: Doc | null, referenceTimestamp: string): Promise<string> {
  if (!req) return '';
  return (await computeEffectiveChecksum(req, referenceTimestamp)).value;
}

/**
 * Drop duplicate (source, eventId) deliveries — the fold contract's
 * idempotency key (ADR-0005 §4). Go parity: dedupEvents.
 */
export function dedupEvents(events: Doc[]): Doc[] {
  const seen = new Set<string>();
  const deduped: Doc[] = [];
  for (const ev of events) {
    if (!ev) continue;
    const key = `${String(ev['source'])}|${String(ev['eventId'])}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(ev);
  }
  return deduped;
}

/**
 * Group events per entity key, each chain ordered by sequence (eventId
 * tie-break), keys sorted for deterministic iteration. Go parity:
 * groupEventChains.
 */
export function groupEventChains(events: Doc[]): { byKey: Map<string, Doc[]>; keys: string[] } {
  const byKey = new Map<string, Doc[]>();
  for (const ev of events) {
    const id = ev['requirementId'] as string;
    const chain = byKey.get(id) ?? [];
    chain.push(ev);
    byKey.set(id, chain);
  }
  const keys = [...byKey.keys()].sort();
  for (const [, chain] of byKey) {
    chain.sort((a, b) => {
      const seqA = a['sequence'] as number;
      const seqB = b['sequence'] as number;
      if (seqA !== seqB) return seqA - seqB;
      return String(a['eventId']).localeCompare(String(b['eventId']));
    });
  }
  return { byKey, keys };
}

/**
 * Walk a per-key chain's priorChecksum links from the seed posture forward,
 * reporting anomalies through keyWarn. Best-effort: expiry anchored to each
 * event's occurrence time. Unanchored chains (key not in seed, first event
 * not new) are left to the caller's application outcome. Go parity:
 * verifyEventChain.
 */
export async function verifyEventChain(
  chain: Doc[],
  seedReq: Doc | null,
  inSeed: boolean,
  keyWarn: (kind: string, message: string) => void,
): Promise<void> {
  const first = chain[0];
  if (!first) return;
  if (!inSeed && first['state'] !== 'new') return;

  let expected = '';
  if (seedReq) {
    expected = await requirementChecksum(seedReq, first['timestamp'] as string);
  }
  for (const ev of chain) {
    const prior = eventPriorValue(ev);
    if (ev['state'] === 'new') {
      if (inSeed) {
        keyWarn('newOnExisting', 'state new for a key already present in the seed');
      } else if (prior !== '') {
        keyWarn('chainGap', 'new-state event carries a non-null priorChecksum');
      }
    } else if (prior !== expected) {
      keyWarn('chainGap', `priorChecksum "${prior}" does not match expected chain state "${expected}"`);
    }
    expected = await requirementChecksum(ev['after'] as Doc | null, ev['timestamp'] as string);
  }
}
