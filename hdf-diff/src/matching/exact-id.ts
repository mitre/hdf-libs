import type { MatchStrategy, MatchResult } from './types.js';

/**
 * Create an exact ID matching strategy.
 *
 * Matches requirements by their `id` field with exact string equality.
 * Confidence is always 1.0 for matches.
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

      // Build a map of new requirements by id, detecting duplicates.
      // When multiple requirements share the same ID, the ID is ambiguous
      // and cannot be used for matching — all duplicates go to unmatchedNew.
      const newById = new Map<string, Record<string, unknown>>();
      const duplicateNewIds = new Set<string>();
      for (const req of newReqs) {
        const id = req['id'];
        if (typeof id === 'string') {
          if (newById.has(id)) {
            // Mark this ID as a duplicate — remove it from the map
            duplicateNewIds.add(id);
            newById.delete(id);
          } else if (!duplicateNewIds.has(id)) {
            newById.set(id, req);
          }
        }
      }

      // Build a map of old requirements by id, detecting duplicates.
      const oldById = new Map<string, Record<string, unknown>>();
      const duplicateOldIds = new Set<string>();
      for (const req of oldReqs) {
        const id = req['id'];
        if (typeof id === 'string') {
          if (oldById.has(id)) {
            duplicateOldIds.add(id);
            oldById.delete(id);
          } else if (!duplicateOldIds.has(id)) {
            oldById.set(id, req);
          }
        }
      }

      // Track which new reqs have been matched
      const matchedNewIds = new Set<string>();

      // Match old requirements against new by id (skip duplicate old IDs)
      for (const oldReq of oldReqs) {
        const id = oldReq['id'];
        if (typeof id !== 'string' || duplicateOldIds.has(id)) {
          result.unmatchedOld.push(oldReq);
          continue;
        }

        const newReq = newById.get(id);
        if (newReq) {
          result.matched.push({
            oldReq,
            newReq,
            strategy: 'exactId',
            confidence: 1.0,
          });
          matchedNewIds.add(id);
        } else {
          result.unmatchedOld.push(oldReq);
        }
      }

      // Collect unmatched new requirements (including all duplicates)
      for (const req of newReqs) {
        const id = req['id'];
        if (typeof id === 'string') {
          if (duplicateNewIds.has(id) || !matchedNewIds.has(id)) {
            result.unmatchedNew.push(req);
          }
        } else {
          result.unmatchedNew.push(req);
        }
      }

      return result;
    },
  };
}
