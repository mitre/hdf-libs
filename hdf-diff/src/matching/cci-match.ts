import type { MatchStrategy, MatchResult } from './types.js';

/**
 * Extract CCI identifiers from a requirement's tags.
 * Looks for `tags.cci` as an array of strings.
 */
function extractCcis(req: Record<string, unknown>): string[] {
  const tags = req['tags'] as Record<string, unknown> | undefined;
  if (!tags) return [];
  const cci = tags['cci'];
  if (!Array.isArray(cci)) return [];
  return cci.filter((c): c is string => typeof c === 'string');
}

/**
 * Create a CCI-based matching strategy.
 *
 * Matches requirements that share the same CCI identifier in `tags.cci`.
 * Only produces a match when exactly one old requirement and exactly one
 * new requirement share a given CCI (unambiguous). Ambiguous CCIs (shared
 * by multiple old or multiple new requirements) are skipped, and those
 * requirements are left unmatched.
 *
 * Confidence is 0.8 for unambiguous matches.
 */
export function createCciMatchStrategy(): MatchStrategy {
  return {
    name: 'cciMatch',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      const result: MatchResult = {
        matched: [],
        unmatchedOld: [],
        unmatchedNew: [],
      };

      // Build CCI -> requirement indices for old and new
      const oldCciMap = new Map<string, number[]>();
      for (let i = 0; i < oldReqs.length; i++) {
        for (const cci of extractCcis(oldReqs[i]!)) {
          const list = oldCciMap.get(cci);
          if (list) {
            list.push(i);
          } else {
            oldCciMap.set(cci, [i]);
          }
        }
      }

      const newCciMap = new Map<string, number[]>();
      for (let i = 0; i < newReqs.length; i++) {
        for (const cci of extractCcis(newReqs[i]!)) {
          const list = newCciMap.get(cci);
          if (list) {
            list.push(i);
          } else {
            newCciMap.set(cci, [i]);
          }
        }
      }

      // Track which indices have been matched
      const matchedOldIndices = new Set<number>();
      const matchedNewIndices = new Set<number>();

      // Find unambiguous CCI matches: exactly 1 old and 1 new share the CCI
      // Collect all CCIs from both maps
      const allCcis = new Set([...oldCciMap.keys(), ...newCciMap.keys()]);

      for (const cci of allCcis) {
        const oldIndices = oldCciMap.get(cci) ?? [];
        const newIndices = newCciMap.get(cci) ?? [];

        if (oldIndices.length !== 1 || newIndices.length !== 1) {
          // Ambiguous or one-sided — skip
          continue;
        }

        const oldIdx = oldIndices[0]!;
        const newIdx = newIndices[0]!;

        // Don't double-match
        if (matchedOldIndices.has(oldIdx) || matchedNewIndices.has(newIdx)) {
          continue;
        }

        result.matched.push({
          oldReq: oldReqs[oldIdx]!,
          newReq: newReqs[newIdx]!,
          strategy: 'cciMatch',
          confidence: 0.8,
        });
        matchedOldIndices.add(oldIdx);
        matchedNewIndices.add(newIdx);
      }

      // Collect unmatched
      for (let i = 0; i < oldReqs.length; i++) {
        if (!matchedOldIndices.has(i)) {
          result.unmatchedOld.push(oldReqs[i]!);
        }
      }
      for (let i = 0; i < newReqs.length; i++) {
        if (!matchedNewIndices.has(i)) {
          result.unmatchedNew.push(newReqs[i]!);
        }
      }

      return result;
    },
  };
}
