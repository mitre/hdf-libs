import type { MatchStrategy, MatchResult } from './types.js';

/**
 * Create a mapped ID matching strategy.
 *
 * Translates old requirement IDs using a mapping table before matching.
 * Only matches requirements whose old ID appears in the mapping table and
 * whose mapped new ID exists in the new requirements.
 *
 * Confidence is 0.95 for mapped matches (slightly less than exact ID
 * because the match depends on the accuracy of the mapping table).
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

      // Build a map of new requirements by id, detecting duplicates.
      // When multiple requirements share the same ID, the ID is ambiguous
      // and cannot be used for matching — all duplicates go to unmatchedNew.
      const newById = new Map<string, Record<string, unknown>>();
      const duplicateNewIds = new Set<string>();
      for (const req of newReqs) {
        const id = req['id'];
        if (typeof id === 'string') {
          if (newById.has(id)) {
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

      // Try to match old requirements using the mapping table (skip duplicate old IDs)
      for (const oldReq of oldReqs) {
        const oldId = oldReq['id'];
        if (typeof oldId !== 'string' || duplicateOldIds.has(oldId)) {
          result.unmatchedOld.push(oldReq);
          continue;
        }

        const mappedNewId = mapping[oldId];
        if (mappedNewId === undefined) {
          result.unmatchedOld.push(oldReq);
          continue;
        }

        // Skip if the mapped new ID is a duplicate
        if (duplicateNewIds.has(mappedNewId)) {
          result.unmatchedOld.push(oldReq);
          continue;
        }

        const newReq = newById.get(mappedNewId);
        if (newReq && !matchedNewIds.has(mappedNewId)) {
          result.matched.push({
            oldReq,
            newReq,
            strategy: 'mappedId',
            confidence: 0.95,
          });
          matchedNewIds.add(mappedNewId);
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
