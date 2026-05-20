import type { MatchStrategy, MatchResult, MatchPair } from './types.js';

/** Default threshold for accepting a Levenshtein match. */
const DEFAULT_ACCEPT_THRESHOLD = 0.45;

/** Modal verbs that mark the start of compliance statements. */
const COMPLIANCE_MODALS = new Set([
  'must', 'will', 'shall', 'should', 'may', 'needs',
]);

/**
 * Compute the Levenshtein edit distance between two strings.
 */
export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  // Use single row optimization
  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j]! + 1,       // deletion
        curr[j - 1]! + 1,   // insertion
        prev[j - 1]! + cost, // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n]!;
}

/**
 * Normalized Levenshtein distance (0.0 = identical, 1.0 = completely different).
 */
export function normalizedLevenshtein(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 0.0;
  return levenshteinDistance(a, b) / maxLen;
}

/**
 * Extract tokens before the first modal verb in a title.
 */
function tokensBeforeModal(title: string): string[] {
  const tokens = title.split(/\s+/).filter((t) => t.length > 0);
  const modalIdx = tokens.findIndex((t) => COMPLIANCE_MODALS.has(t.toLowerCase()));
  return modalIdx === -1 ? tokens : tokens.slice(0, modalIdx);
}

/**
 * Auto-detect the dominant vendor prefix in a corpus of titles.
 *
 * Tries progressively shorter leading-token prefixes. Returns the prefix
 * that appears in > 50% of titles, stopping before modal verbs.
 * Returns '' when no prefix reaches the threshold.
 */
export function autoDetectPrefix(titles: string[], threshold = 0.5): string {
  if (titles.length === 0) return '';

  const leading = titles.map((t) => tokensBeforeModal(t));
  const maxLen = Math.max(...leading.map((l) => l.length));

  for (let n = maxLen; n > 0; n--) {
    const counts = new Map<string, number>();
    for (const l of leading) {
      if (l.length >= n) {
        const key = l.slice(0, n).join(' ');
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
    let bestKey = '';
    let bestCount = 0;
    for (const [key, count] of counts) {
      if (count > bestCount) {
        bestKey = key;
        bestCount = count;
      }
    }
    if (bestCount / titles.length > threshold) {
      return bestKey;
    }
  }
  return '';
}

/**
 * Strip a detected vendor prefix from a title.
 */
export function normalizeTitle(title: string, prefix: string): string {
  if (!prefix) return title;
  if (title === prefix) return '';
  if (title.startsWith(prefix + ' ')) return title.slice(prefix.length + 1);
  return title;
}

/**
 * Extract title string from a requirement.
 */
function safeTitle(req: Record<string, unknown>): string {
  const title = req['title'];
  return typeof title === 'string' ? title : '';
}

/**
 * Create a vendor fuzzy title matching strategy (Tier 3 of the delta pipeline).
 *
 * Cross-vendor matching with auto-detected vendor prefix stripping.
 * Uses normalized Levenshtein distance to compare titles after removing
 * the dominant vendor prefix (e.g., "RHEL 9" or "Amazon Linux 2023").
 *
 * Accepts matches below threshold 0.45 (confidence = 1.0 - distance).
 * Greedy best-match.
 *
 * @param acceptThreshold Max normalized Levenshtein distance to accept (default: 0.45)
 */
export function createVendorFuzzyTitleStrategy(acceptThreshold?: number): MatchStrategy {
  const threshold = acceptThreshold ?? DEFAULT_ACCEPT_THRESHOLD;

  return {
    name: 'vendorFuzzyTitle',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      // Collect titles for prefix detection
      const oldTitles = oldReqs.map(safeTitle).filter((t) => t.length > 0);
      const newTitles = newReqs.map(safeTitle).filter((t) => t.length > 0);
      const oldPrefix = autoDetectPrefix(oldTitles);
      const newPrefix = autoDetectPrefix(newTitles);

      // Build candidates with normalized titles
      type IndexedTitle = { idx: number; normalized: string };
      const oldNorm: IndexedTitle[] = [];
      for (let i = 0; i < oldReqs.length; i++) {
        const t = safeTitle(oldReqs[i]!);
        if (t) {
          oldNorm.push({ idx: i, normalized: normalizeTitle(t, oldPrefix) });
        }
      }
      const newNorm: IndexedTitle[] = [];
      for (let i = 0; i < newReqs.length; i++) {
        const t = safeTitle(newReqs[i]!);
        if (t) {
          newNorm.push({ idx: i, normalized: normalizeTitle(t, newPrefix) });
        }
      }

      // Compute all pairwise distances
      const candidates: Array<{
        oldIdx: number;
        newIdx: number;
        distance: number;
      }> = [];

      for (const old of oldNorm) {
        for (const nw of newNorm) {
          if (!old.normalized || !nw.normalized) continue;
          const dist = normalizedLevenshtein(old.normalized, nw.normalized);
          if (dist < threshold) {
            candidates.push({
              oldIdx: old.idx,
              newIdx: nw.idx,
              distance: dist,
            });
          }
        }
      }

      // Sort by distance ascending (best matches first)
      candidates.sort((a, b) => a.distance - b.distance);

      // Greedy assignment
      const matched: MatchPair[] = [];
      const matchedOldIndices = new Set<number>();
      const matchedNewIndices = new Set<number>();

      for (const c of candidates) {
        if (matchedOldIndices.has(c.oldIdx) || matchedNewIndices.has(c.newIdx)) continue;

        matched.push({
          oldReq: oldReqs[c.oldIdx]!,
          newReq: newReqs[c.newIdx]!,
          strategy: 'vendorFuzzyTitle',
          confidence: 1.0 - c.distance,
          relationship: 'primary',
        });
        matchedOldIndices.add(c.oldIdx);
        matchedNewIndices.add(c.newIdx);
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
