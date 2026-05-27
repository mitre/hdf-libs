import type { MatchStrategy, MatchResult, MatchPair } from './types.js';

/**
 * Default minimum Jaccard similarity for a package-set match.
 *
 * 0.5 means at least half of the union of (name, version) tuples must
 * appear on both sides. This is permissive enough to catch CVE/GHSA
 * advisories that list overlapping but not identical package versions,
 * while still rejecting unrelated findings that happen to share one
 * common dependency.
 */
const DEFAULT_MIN_JACCARD = 0.5;

/**
 * Extract a deduplicated set of `name@version` tuples from a requirement's
 * `affectedPackages[]` field. Entries that are not objects with both a
 * string `name` and string `version` are silently dropped.
 */
function extractPackageTuples(req: Record<string, unknown>): Set<string> {
  const raw = req['affectedPackages'];
  if (!Array.isArray(raw)) return new Set();

  const tuples = new Set<string>();
  for (const entry of raw) {
    if (entry === null || typeof entry !== 'object') continue;
    const obj = entry as Record<string, unknown>;
    const name = obj['name'];
    const version = obj['version'];
    if (typeof name !== 'string' || typeof version !== 'string') continue;
    tuples.add(`${name}@${version}`);
  }
  return tuples;
}

/**
 * Jaccard similarity between two sets of strings.
 * Returns 0 when both sets are empty.
 */
function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let intersection = 0;
  for (const x of a) {
    if (b.has(x)) intersection++;
  }
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/**
 * Create a package-set matching strategy.
 *
 * For requirements with `affectedPackages[]` populated, builds a set of
 * `"name@version"` tuples and matches pairs whose Jaccard similarity is
 * at least `minJaccard` (default 0.5). Useful when CVE identifiers differ
 * across scanners (for example, GHSA-XXXX-XXXX vs CVE-YYYY-N for the same
 * underlying vulnerability) but the affected-package signatures align.
 *
 * Greedy: each new requirement is paired with the highest-scoring old
 * requirement still available. Each old requirement matches at most once.
 *
 * @param minJaccard Minimum Jaccard similarity for a match (default 0.5).
 */
export function createPackageMatchStrategy(
  minJaccard: number = DEFAULT_MIN_JACCARD,
): MatchStrategy {
  return {
    name: 'packageMatch',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      // Precompute tuple sets for both sides.
      const oldTuples = oldReqs.map(extractPackageTuples);
      const newTuples = newReqs.map(extractPackageTuples);

      const matched: MatchPair[] = [];
      const matchedOldIndices = new Set<number>();
      const matchedNewIndices = new Set<number>();

      // Greedy: walk each new req, find the best available old req above threshold.
      for (let ni = 0; ni < newReqs.length; ni++) {
        const nSet = newTuples[ni]!;
        if (nSet.size === 0) continue;

        let bestIdx = -1;
        let bestScore = -1;
        for (let oi = 0; oi < oldReqs.length; oi++) {
          if (matchedOldIndices.has(oi)) continue;
          const oSet = oldTuples[oi]!;
          if (oSet.size === 0) continue;
          const score = jaccard(nSet, oSet);
          if (score >= minJaccard && score > bestScore) {
            bestScore = score;
            bestIdx = oi;
          }
        }

        if (bestIdx >= 0) {
          matched.push({
            oldReq: oldReqs[bestIdx]!,
            newReq: newReqs[ni]!,
            strategy: 'packageMatch',
            confidence: bestScore,
          });
          matchedOldIndices.add(bestIdx);
          matchedNewIndices.add(ni);
        }
      }

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
