import type { MatchStrategy, MatchResult } from './types.js';

/** Common English stop words to exclude from tokenization */
const STOP_WORDS = new Set([
  'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
  'should', 'may', 'might', 'shall', 'can', 'to', 'of', 'in', 'for',
  'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
  'before', 'after', 'above', 'below', 'between', 'out', 'off', 'over',
  'under', 'again', 'further', 'then', 'once', 'and', 'but', 'or', 'nor',
  'not', 'no', 'so', 'if', 'it', 'its', 'that', 'this', 'these', 'those',
  'each', 'every', 'all', 'both', 'few', 'more', 'most', 'other', 'some',
  'such', 'than', 'too', 'very', 'just', 'about',
]);

/**
 * Tokenize a title string into a set of meaningful tokens.
 *
 * - Lowercases the string
 * - Splits on whitespace and punctuation
 * - Filters out common stop words
 * - Returns unique tokens as a Set
 */
export function tokenize(text: string): Set<string> {
  if (!text) return new Set();

  const tokens = text
    .toLowerCase()
    .split(/[\s\-_/\\,.;:!?()[\]{}"']+/)
    .filter((t) => t.length > 0 && !STOP_WORDS.has(t));

  return new Set(tokens);
}

/**
 * Compute Jaccard similarity between two sets.
 * Returns |intersection| / |union|, or 0 if both sets are empty.
 */
export function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0.0;

  let intersectionSize = 0;
  // Iterate over the smaller set for efficiency
  const [smaller, larger] = a.size <= b.size ? [a, b] : [b, a];
  for (const item of smaller) {
    if (larger.has(item)) {
      intersectionSize++;
    }
  }

  const unionSize = a.size + b.size - intersectionSize;
  // Unreachable: if both sets are empty, we return above. If either is non-empty, unionSize > 0.
  // Guard kept for mathematical correctness.
  /* c8 ignore next */
  if (unionSize === 0) return 0.0;

  return intersectionSize / unionSize;
}

/**
 * Default minimum confidence threshold for fuzzy title matching.
 */
const DEFAULT_MIN_CONFIDENCE = 0.6;

/**
 * Create a fuzzy title matching strategy.
 *
 * Matches requirements by token-based Jaccard similarity on the `title` field.
 * Uses greedy best-match: for each unmatched old requirement, finds the
 * best-matching unmatched new requirement above the confidence threshold.
 *
 * @param minConfidence Minimum Jaccard similarity to accept a match (default: 0.6)
 */
export function createFuzzyTitleStrategy(minConfidence?: number): MatchStrategy {
  const threshold = minConfidence ?? DEFAULT_MIN_CONFIDENCE;

  return {
    name: 'fuzzyTitle',
    match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult {
      const result: MatchResult = {
        matched: [],
        unmatchedOld: [],
        unmatchedNew: [],
      };

      // Pre-tokenize all titles
      const oldTokens: Array<{ idx: number; tokens: Set<string> }> = [];
      for (let i = 0; i < oldReqs.length; i++) {
        const title = oldReqs[i]!['title'];
        if (typeof title === 'string' && title.length > 0) {
          const tokens = tokenize(title);
          if (tokens.size > 0) {
            oldTokens.push({ idx: i, tokens });
          }
        }
      }

      const newTokens: Array<{ idx: number; tokens: Set<string> }> = [];
      for (let i = 0; i < newReqs.length; i++) {
        const title = newReqs[i]!['title'];
        if (typeof title === 'string' && title.length > 0) {
          const tokens = tokenize(title);
          if (tokens.size > 0) {
            newTokens.push({ idx: i, tokens });
          }
        }
      }

      // Track matched indices
      const matchedOldIndices = new Set<number>();
      const matchedNewIndices = new Set<number>();

      // Build a list of all potential matches with similarity scores
      const candidates: Array<{
        oldIdx: number;
        newIdx: number;
        similarity: number;
      }> = [];

      for (const old of oldTokens) {
        for (const nw of newTokens) {
          const sim = jaccardSimilarity(old.tokens, nw.tokens);
          if (sim >= threshold) {
            candidates.push({
              oldIdx: old.idx,
              newIdx: nw.idx,
              similarity: sim,
            });
          }
        }
      }

      // Sort by similarity descending (greedy best-match)
      candidates.sort((a, b) => b.similarity - a.similarity);

      // Greedily assign matches
      for (const candidate of candidates) {
        if (matchedOldIndices.has(candidate.oldIdx) || matchedNewIndices.has(candidate.newIdx)) {
          continue;
        }

        result.matched.push({
          oldReq: oldReqs[candidate.oldIdx]!,
          newReq: newReqs[candidate.newIdx]!,
          strategy: 'fuzzyTitle',
          confidence: candidate.similarity,
        });
        matchedOldIndices.add(candidate.oldIdx);
        matchedNewIndices.add(candidate.newIdx);
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
