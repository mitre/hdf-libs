/**
 * Index and pairing helpers for the id-based strategies; peer of go/matching/util.go.
 * A repeated id is legal: the id names the requirement, not the finding. It was once
 * called ambiguous and left unmatched, so a self-comparison reported every occurrence
 * absent AND new.
 */

/** Groups requirement positions by id. Entries without a string id are left out. */
export function buildIdIndex(reqs: Record<string, unknown>[]): Map<string, number[]> {
  const byId = new Map<string, number[]>();
  for (const [i, req] of reqs.entries()) {
    const id = req['id'];
    if (typeof id !== 'string') continue;
    const at = byId.get(id);
    if (at) {
      at.push(i);
      continue;
    }
    byId.set(id, [i]);
  }
  return byId;
}

/** Keys in a fixed order, so the Go peer's struct marshalling and this agree on which
 * occurrences count as the same. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

/**
 * Discriminates occurrences that share an id: code, title and affectedPackages, with
 * position as the tie-break in pairOccurrences. `results` is excluded because its
 * startTime and runTime vary per run.
 */
export function contentKey(req: Record<string, unknown>): string {
  return canonical({
    code: req['code'] ?? null,
    title: req['title'] ?? null,
    affectedPackages: req['affectedPackages'] ?? null,
  });
}

export interface OccurrencePairing {
  pairs: [number, number][];
  surplusOld: number[];
  surplusNew: number[];
}

/** Pairs one id's occurrences by content key, then document order within a key,
 * reporting the surplus on each side. */
export function pairOccurrences(
  oldIdx: number[],
  newIdx: number[],
  oldReqs: Record<string, unknown>[],
  newReqs: Record<string, unknown>[],
): OccurrencePairing {
  if (oldIdx.length === 1 && newIdx.length === 1) {
    return { pairs: [[oldIdx[0]!, newIdx[0]!]], surplusOld: [], surplusNew: [] };
  }

  const newByContent = new Map<string, number[]>();
  for (const i of newIdx) {
    const key = contentKey(newReqs[i]!);
    const queue = newByContent.get(key);
    if (queue) {
      queue.push(i);
      continue;
    }
    newByContent.set(key, [i]);
  }

  const pairs: [number, number][] = [];
  const taken = new Set<number>();
  const leftover: number[] = [];
  for (const oi of oldIdx) {
    const queue = newByContent.get(contentKey(oldReqs[oi]!));
    const ni = queue?.shift();
    if (ni === undefined) {
      leftover.push(oi);
      continue;
    }
    taken.add(ni);
    pairs.push([oi, ni]);
  }

  // What no content key claimed pairs in document order, settling indistinguishable
  // occurrences.
  const free = newIdx.filter((i) => !taken.has(i));
  const n = Math.min(leftover.length, free.length);
  for (let k = 0; k < n; k++) {
    pairs.push([leftover[k]!, free[k]!]);
  }
  return { pairs, surplusOld: leftover.slice(n), surplusNew: free.slice(n) };
}
