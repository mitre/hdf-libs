import type { MatchStrategy, MatchResult } from './types.js';
import { buildIdIndex, pairOccurrences } from './util.js';

/**
 * Create an exact ID matching strategy.
 *
 * Matches requirements by `id` with exact string equality. An id carried by several
 * entries names one requirement reported several times, so pairOccurrences pairs those
 * among themselves. Confidence is always 1.0 for matches.
 */
export function createExactIdStrategy(): MatchStrategy {
  return {
    name: 'exactId',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      const result: MatchResult = {
        matched: [],
        unmatchedOld: [],
        unmatchedNew: [],
      };

      const oldById = buildIdIndex(oldReqs);
      const newById = buildIdIndex(newReqs);

      // Document order, one id at a time: the order must not depend on map iteration,
      // because the Go half emits the same one.
      const pairedWith = new Map<number, number>();
      const pairedNew = new Set<number>();
      const seen = new Set<string>();
      for (const oldReq of oldReqs) {
        const id = oldReq['id'];
        if (typeof id !== 'string' || seen.has(id)) continue;
        seen.add(id);
        const { pairs } = pairOccurrences(
          oldById.get(id) ?? [],
          newById.get(id) ?? [],
          oldReqs,
          newReqs,
        );
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
          strategy: 'exactId',
          confidence: 1.0,
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
