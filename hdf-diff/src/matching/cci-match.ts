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
 * Extract CWE identifiers from a requirement.
 *
 * Prefers the structured `req.cwe[]` field (introduced in Evaluated_Requirement
 * Wave 1) when present and non-empty. Falls back to `tags.cwe` for compatibility
 * with HDF files emitted before the structured field existed. `tags.cwe` may be
 * either an array of strings or a single string.
 *
 * Exported for reuse by sibling matchers (e.g. srg-cci-tiebreak) and to make
 * the preference order directly testable.
 */
export function extractCwes(req: Record<string, unknown>): string[] {
  const cwe = req['cwe'];
  if (Array.isArray(cwe)) {
    const filtered = cwe.filter((c): c is string => typeof c === 'string');
    if (filtered.length > 0) return filtered;
  }
  const tags = req['tags'] as Record<string, unknown> | undefined;
  if (!tags) return [];
  const tagCwe = tags['cwe'];
  if (Array.isArray(tagCwe)) {
    return tagCwe.filter((c): c is string => typeof c === 'string');
  }
  if (typeof tagCwe === 'string') {
    return [tagCwe];
  }
  return [];
}

/**
 * Build a key → [requirement-indices] map for unambiguous-pair lookup.
 */
function indexByKey(
  reqs: Record<string, unknown>[],
  keys: (req: Record<string, unknown>) => string[],
): Map<string, number[]> {
  const map = new Map<string, number[]>();
  for (let i = 0; i < reqs.length; i++) {
    for (const key of keys(reqs[i]!)) {
      const list = map.get(key);
      if (list) {
        list.push(i);
      } else {
        map.set(key, [i]);
      }
    }
  }
  return map;
}

/**
 * Pair indices by an unambiguous shared key (exactly 1 old + 1 new per key),
 * skipping any indices already claimed in `matchedOld` / `matchedNew`.
 */
function pairUnambiguous(
  oldMap: Map<string, number[]>,
  newMap: Map<string, number[]>,
  matchedOld: Set<number>,
  matchedNew: Set<number>,
): Array<{ oldIdx: number; newIdx: number }> {
  const pairs: Array<{ oldIdx: number; newIdx: number }> = [];
  const allKeys = new Set([...oldMap.keys(), ...newMap.keys()]);
  for (const key of allKeys) {
    const oldIndices = oldMap.get(key) ?? [];
    const newIndices = newMap.get(key) ?? [];
    if (oldIndices.length !== 1 || newIndices.length !== 1) continue;
    const oldIdx = oldIndices[0]!;
    const newIdx = newIndices[0]!;
    if (matchedOld.has(oldIdx) || matchedNew.has(newIdx)) continue;
    pairs.push({ oldIdx, newIdx });
    matchedOld.add(oldIdx);
    matchedNew.add(newIdx);
  }
  return pairs;
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
 * As a fallback, also pairs unambiguous CWE matches (preferring the
 * structured `req.cwe[]` field over the legacy `tags.cwe`). This catches
 * CVE-ecosystem findings where CCI is absent but CWE is present.
 *
 * Confidence is 0.8 for CCI matches and 0.6 for CWE-fallback matches.
 */
export function createCciMatchStrategy(): MatchStrategy {
  return {
    name: 'cciMatch',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      const matchedOldIndices = new Set<number>();
      const matchedNewIndices = new Set<number>();
      const matched: MatchResult['matched'] = [];

      // Primary signal: CCI.
      const oldCciMap = indexByKey(oldReqs, extractCcis);
      const newCciMap = indexByKey(newReqs, extractCcis);
      for (const { oldIdx, newIdx } of pairUnambiguous(
        oldCciMap,
        newCciMap,
        matchedOldIndices,
        matchedNewIndices,
      )) {
        matched.push({
          oldReq: oldReqs[oldIdx]!,
          newReq: newReqs[newIdx]!,
          strategy: 'cciMatch',
          confidence: 0.8,
        });
      }

      // Fallback signal: CWE (structured field preferred over tags.cwe).
      // All reqs are indexed here; pairUnambiguous skips any already claimed by
      // CCI pairing via the matchedOld/NewIndices sets passed below.
      const oldCweMap = indexByKey(oldReqs, (r) => extractCwes(r));
      const newCweMap = indexByKey(newReqs, (r) => extractCwes(r));
      for (const { oldIdx, newIdx } of pairUnambiguous(
        oldCweMap,
        newCweMap,
        matchedOldIndices,
        matchedNewIndices,
      )) {
        matched.push({
          oldReq: oldReqs[oldIdx]!,
          newReq: newReqs[newIdx]!,
          strategy: 'cciMatch',
          confidence: 0.6,
        });
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
