import type { MatchStrategy, MatchResult } from './types.js';
import { buildIdIndex, pairOccurrences } from './util.js';

/**
 * Create a mapped ID matching strategy.
 *
 * Translates old requirement IDs using a mapping table before matching. Only matches
 * requirements whose old ID appears in the table and whose mapped new ID exists. As in
 * the exact-id strategy, a repeated id's occurrences pair among themselves.
 *
 * Confidence is 0.95, slightly less than exact ID because the match depends on the
 * accuracy of the mapping table.
 */
export function createMappedIdStrategy(mapping: Record<string, string>): MatchStrategy {
  return {
    name: 'mappedId',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      const result: MatchResult = {
        matched: [],
        unmatchedOld: [],
        unmatchedNew: [],
      };

      const oldById = buildIdIndex(oldReqs);
      const newById = buildIdIndex(newReqs);

      const pairedWith = new Map<number, number>();
      const pairedNew = new Set<number>();
      const seen = new Set<string>();
      for (const oldReq of oldReqs) {
        const oldId = oldReq['id'];
        if (typeof oldId !== 'string' || seen.has(oldId)) continue;
        seen.add(oldId);
        const mappedNewId = mapping[oldId];
        if (mappedNewId === undefined) continue;
        // Several old ids may map to one new id, so an occurrence another id already
        // claimed is not offered again, or one entry is matched twice.
        const candidates = (newById.get(mappedNewId) ?? []).filter((i) => !pairedNew.has(i));
        const { pairs } = pairOccurrences(oldById.get(oldId) ?? [], candidates, oldReqs, newReqs);
        for (const [oi, ni] of pairs) {
          pairedWith.set(oi, ni);
          pairedNew.add(ni);
        }
      }

      for (const [i, oldReq] of oldReqs.entries()) {
        const newIdx = pairedWith.get(i);
        if (newIdx === undefined) {
          result.unmatchedOld.push(oldReq);
          continue;
        }
        result.matched.push({
          oldReq,
          newReq: newReqs[newIdx]!,
          strategy: 'mappedId',
          confidence: 0.95,
        });
      }

      for (const [i, req] of newReqs.entries()) {
        if (!pairedNew.has(i)) {
          result.unmatchedNew.push(req);
        }
      }

      return result;
    },
  };
}
