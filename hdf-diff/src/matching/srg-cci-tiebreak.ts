import type { MatchStrategy, MatchResult, MatchPair } from './types.js';

/** Composite score weights matching SAF CLI's Tier 2. */
const CCI_WEIGHT = 0.7;
const TITLE_WEIGHT = 0.3;

/**
 * Extract CCI identifiers from a requirement's tags.cci.
 */
function extractCcis(req: Record<string, unknown>): Set<string> {
  const tags = req['tags'] as Record<string, unknown> | undefined;
  if (!tags) return new Set();
  const cci = tags['cci'];
  if (!Array.isArray(cci)) return new Set();
  return new Set(cci.filter((c): c is string => typeof c === 'string'));
}

/**
 * Extract CWE identifiers from a requirement.
 *
 * Prefers the structured `req.cwe[]` field (introduced in Evaluated_Requirement
 * Wave 1) when present and non-empty. Falls back to `tags.cwe` (array or string)
 * for compatibility with HDF files emitted before the structured field existed.
 *
 * Exported so callers and tests can verify the preference order directly.
 */
export function extractCwes(req: Record<string, unknown>): Set<string> {
  const cwe = req['cwe'];
  if (Array.isArray(cwe)) {
    const filtered = cwe.filter((c): c is string => typeof c === 'string');
    if (filtered.length > 0) return new Set(filtered);
  }
  const tags = req['tags'] as Record<string, unknown> | undefined;
  if (!tags) return new Set();
  const tagCwe = tags['cwe'];
  if (Array.isArray(tagCwe)) {
    return new Set(tagCwe.filter((c): c is string => typeof c === 'string'));
  }
  if (typeof tagCwe === 'string') {
    return new Set([tagCwe]);
  }
  return new Set();
}

/**
 * Extract tags.gtitle from a requirement.
 */
function extractGtitle(req: Record<string, unknown>): string | null {
  const tags = req['tags'] as Record<string, unknown> | undefined;
  if (!tags) return null;
  const gtitle = tags['gtitle'];
  if (typeof gtitle !== 'string' || gtitle === '') return null;
  return gtitle;
}

/**
 * Extract title from a requirement.
 */
function safeTitle(req: Record<string, unknown>): string {
  const title = req['title'];
  return typeof title === 'string' ? title : '';
}

/**
 * Jaccard similarity between two sets.
 */
function cciJaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let intersectionSize = 0;
  for (const x of a) {
    if (b.has(x)) intersectionSize++;
  }
  const unionSize = a.size + b.size - intersectionSize;
  return intersectionSize / unionSize;
}

/**
 * Simple whitespace-split token Jaccard similarity.
 */
function tokenJaccard(a: string, b: string): number {
  const ta = new Set(
    a
      .toLowerCase()
      .split(/\s+/)
      .filter((t) => t.length > 0),
  );
  const tb = new Set(
    b
      .toLowerCase()
      .split(/\s+/)
      .filter((t) => t.length > 0),
  );
  if (ta.size === 0 || tb.size === 0) return 0;
  let intersectionSize = 0;
  for (const x of ta) {
    if (tb.has(x)) intersectionSize++;
  }
  const unionSize = ta.size + tb.size - intersectionSize;
  return intersectionSize / unionSize;
}

/**
 * Create an SRG CCI Tiebreak matching strategy (Tier 2 of the delta pipeline).
 *
 * Handles ambiguous SRG matches where multiple old or new requirements share
 * the same tags.gtitle. Uses a composite score of CCI Jaccard (70%) and
 * token Jaccard on titles (30%) to pick the best match.
 *
 * Only activates for gtitle groups with multiple candidates (>1 old or >1 new).
 * 1:1 matches are left for srgDeterministic (Tier 1).
 */
export function createSrgCciTiebreakStrategy(): MatchStrategy {
  return {
    name: 'srgCciTiebreak',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      // Build gtitle → indices
      const oldGtitleMap = new Map<string, number[]>();
      for (let i = 0; i < oldReqs.length; i++) {
        const g = extractGtitle(oldReqs[i]!);
        if (g) {
          const list = oldGtitleMap.get(g);
          if (list) list.push(i);
          else oldGtitleMap.set(g, [i]);
        }
      }

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

      for (const [gtitle, newIdxList] of newGtitleMap) {
        const oldIdxList = oldGtitleMap.get(gtitle);
        if (!oldIdxList || oldIdxList.length === 0) continue;

        const nc = newIdxList.length;
        const oc = oldIdxList.length;

        // Only handle ambiguous cases (at least one side > 1)
        // 1:1 is handled by srgDeterministic
        if (nc === 1 && oc === 1) continue;

        // Greedy matching: process each new req, find best old candidate
        for (const ni of newIdxList) {
          if (matchedNewIndices.has(ni)) continue;

          const newCcis = extractCcis(newReqs[ni]!);
          const newTitle = safeTitle(newReqs[ni]!);
          const newCwes = extractCwes(newReqs[ni]!);

          let bestIdx = -1;
          let bestComposite = -1;
          let bestCci = 0;
          let bestCwe = -1;
          let bestIsUnclaimed = false;

          for (const oi of oldIdxList) {
            const oldCcis = extractCcis(oldReqs[oi]!);
            const oldTitle = safeTitle(oldReqs[oi]!);
            const oldCwes = extractCwes(oldReqs[oi]!);

            const cci = cciJaccard(newCcis, oldCcis);
            const title = tokenJaccard(newTitle, oldTitle);
            // CWE Jaccard is used purely as a tiebreaker — it does NOT
            // change composite scoring weights, so existing tests that
            // depend on CCI+title ordering are unaffected.
            const cwe = cciJaccard(newCwes, oldCwes);
            const composite = CCI_WEIGHT * cci + TITLE_WEIGHT * title;
            const isUnclaimed = !matchedOldIndices.has(oi);

            // Prefer unclaimed candidates; among same claim status, prefer
            // higher composite; among equal composites, prefer higher CWE
            // Jaccard (tiebreaker added Wave 2).
            if (
              bestIdx === -1 ||
              (isUnclaimed && !bestIsUnclaimed) ||
              (isUnclaimed === bestIsUnclaimed && composite > bestComposite) ||
              (isUnclaimed === bestIsUnclaimed &&
                composite === bestComposite &&
                cwe > bestCwe)
            ) {
              bestIdx = oi;
              bestComposite = composite;
              bestCci = cci;
              bestCwe = cwe;
              bestIsUnclaimed = isUnclaimed;
            }
          }

          if (bestIdx >= 0) {
            const relationship = matchedOldIndices.has(bestIdx) ? 'related' : 'primary';
            matched.push({
              oldReq: oldReqs[bestIdx]!,
              newReq: newReqs[ni]!,
              strategy: 'srgCciTiebreak',
              confidence: Math.max(bestCci, 0),
              relationship,
            });
            matchedOldIndices.add(bestIdx);
            matchedNewIndices.add(ni);
          }
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
