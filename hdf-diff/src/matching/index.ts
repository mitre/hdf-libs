import type { MatchResult, MatchStrategy } from './types.js';
import { createExactIdStrategy } from './exact-id.js';
import { createMappedIdStrategy } from './mapped-id.js';
import { createCciMatchStrategy } from './cci-match.js';
import { createFuzzyTitleStrategy } from './fuzzy-match.js';

// Re-export types and factory functions
export type { MatchResult, MatchPair, MatchStrategy } from './types.js';
export { createExactIdStrategy } from './exact-id.js';
export { createMappedIdStrategy } from './mapped-id.js';
export { createCciMatchStrategy } from './cci-match.js';
export { createFuzzyTitleStrategy, tokenize, jaccardSimilarity } from './fuzzy-match.js';

/**
 * Options for configuring requirement matching.
 */
export interface MatchOptions {
  /** Primary matching strategy name (default: 'exactId') */
  strategy?: string;
  /** Fallback strategy names, applied in order to remaining unmatched requirements */
  fallbackStrategies?: string[];
  /** Mapping table for the 'mappedId' strategy (old ID -> new ID) */
  mappingTable?: Record<string, string>;
  /** Minimum confidence threshold for fuzzy matching (default: 0.6) */
  minConfidence?: number;
}

/**
 * Create a strategy instance by name, using the provided options for
 * strategies that require configuration.
 */
function createStrategy(name: string, options: MatchOptions): MatchStrategy {
  switch (name) {
    case 'exactId':
      return createExactIdStrategy();
    case 'mappedId':
      return createMappedIdStrategy(options.mappingTable ?? {});
    case 'cciMatch':
      return createCciMatchStrategy();
    case 'fuzzyTitle':
      return createFuzzyTitleStrategy(options.minConfidence);
    default:
      throw new Error(`Unknown matching strategy: '${name}'`);
  }
}

/**
 * Match requirements between two evaluations using a primary strategy
 * and optional fallback strategies.
 *
 * The registry applies strategies in order:
 * 1. Primary strategy matches what it can
 * 2. Unmatched requirements pass to the next fallback strategy
 * 3. Process continues until all strategies are exhausted or all
 *    requirements are matched
 *
 * @param oldReqs Requirements from the old evaluation
 * @param newReqs Requirements from the new evaluation
 * @param options Matching configuration
 * @returns Combined match result from all strategies
 */
export function matchRequirements(
  oldReqs: Record<string, unknown>[],
  newReqs: Record<string, unknown>[],
  options?: MatchOptions,
): MatchResult {
  const opts = options ?? {};
  const primaryName = opts.strategy ?? 'exactId';
  const fallbackNames = opts.fallbackStrategies ?? [];

  // Build all strategy instances once up front (also validates names —
  // createStrategy throws for unknown strategy names).
  const allNames = [primaryName, ...fallbackNames];
  const strategies = allNames.map((name) => createStrategy(name, opts));

  // Accumulate all matched pairs
  const allMatched: MatchResult['matched'] = [];

  // Start with all requirements unmatched
  let currentUnmatchedOld = oldReqs;
  let currentUnmatchedNew = newReqs;

  // Apply strategies in order
  for (const strategy of strategies) {
    if (currentUnmatchedOld.length === 0 || currentUnmatchedNew.length === 0) {
      break;
    }

    const result = strategy.match(currentUnmatchedOld, currentUnmatchedNew);

    allMatched.push(...result.matched);
    currentUnmatchedOld = result.unmatchedOld;
    currentUnmatchedNew = result.unmatchedNew;
  }

  return {
    matched: allMatched,
    unmatchedOld: currentUnmatchedOld,
    unmatchedNew: currentUnmatchedNew,
  };
}
