import type { MatchStrategy, MatchResult, MatchPair } from './types.js';

/**
 * Extract the SRG-OS ID from a requirement's tags.gtitle field.
 * Returns null if missing or not a string.
 */
function extractGtitle(req: Record<string, unknown>): string | null {
  const tags = req['tags'] as Record<string, unknown> | undefined;
  if (!tags) return null;
  const gtitle = tags['gtitle'];
  if (typeof gtitle !== 'string' || gtitle === '') return null;
  return gtitle;
}

/**
 * Create a deterministic SRG matching strategy (Tier 1 of the delta pipeline).
 *
 * Matches requirements by exact `tags.gtitle` (SRG-OS requirement ID).
 *
 * For each gtitle shared between old and new:
 * - 1 old + 1 new → single MatchPair (confidence 1.0, relationship "primary")
 * - 1 new + N old → N MatchPairs (first old "primary", rest "related")
 * - N new + 1 old → N MatchPairs (first new "primary", rest "related")
 * - N:M (both > 1) → skip, leave for fallback strategies
 *
 * Requirements without a gtitle pass through as unmatched.
 */
export function createSrgDeterministicStrategy(): MatchStrategy {
  return {
    name: 'srgDeterministic',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      // Build gtitle → indices for old
      const oldGtitleMap = new Map<string, number[]>();
      for (let i = 0; i < oldReqs.length; i++) {
        const g = extractGtitle(oldReqs[i]!);
        if (g) {
          const list = oldGtitleMap.get(g);
          if (list) list.push(i);
          else oldGtitleMap.set(g, [i]);
        }
      }

      // Build gtitle → indices for new
      const newGtitleMap = new Map<string, number[]>();
      for (let i = 0; i < newReqs.length; i++) {
        const g = extractGtitle(newReqs[i]!);
        if (g) {
          const list = newGtitleMap.get(g);
          if (list) list.push(i);
          else newGtitleMap.set(g, [i]);
        }
      }

      const matched: MatchPair[] = [];
      const matchedOldIndices = new Set<number>();
      const matchedNewIndices = new Set<number>();
      // Track which old indices have been claimed as "primary"
      const claimedOldIndices = new Set<number>();

      for (const [gtitle, newIdxList] of newGtitleMap) {
        const oldIdxList = oldGtitleMap.get(gtitle);
        if (!oldIdxList || oldIdxList.length === 0) continue;

        const nc = newIdxList.length;
        const oc = oldIdxList.length;

        // N:M ambiguous — skip
        if (nc > 1 && oc > 1) continue;

        // Create match pairs
        for (const ni of newIdxList) {
          let primaryOldSet = false;
          for (const oi of oldIdxList) {
            let relationship: 'primary' | 'related';
            if (oc === 1) {
              // 1 old, possibly multiple new → claim tracking
              relationship = claimedOldIndices.has(oi) ? 'related' : 'primary';
              if (relationship === 'primary') claimedOldIndices.add(oi);
            } else {
              // Multiple old, 1 new → first old is primary
              relationship = primaryOldSet ? 'related' : 'primary';
              primaryOldSet = true;
            }

            matched.push({
              oldReq: oldReqs[oi]!,
              newReq: newReqs[ni]!,
              strategy: 'srgDeterministic',
              confidence: 1.0,
              relationship,
            });
            matchedOldIndices.add(oi);
          }
          matchedNewIndices.add(ni);
        }
      }

      // Collect unmatched
      const unmatchedOld: Record<string, unknown>[] = [];
      for (let i = 0; i < oldReqs.length; i++) {
        if (!matchedOldIndices.has(i)) unmatchedOld.push(oldReqs[i]!);
      }
      const unmatchedNew: Record<string, unknown>[] = [];
      for (let i = 0; i < newReqs.length; i++) {
        if (!matchedNewIndices.has(i)) unmatchedNew.push(newReqs[i]!);
      }

      return { matched, unmatchedOld, unmatchedNew };
    },
  };
}
