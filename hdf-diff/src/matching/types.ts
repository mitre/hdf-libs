/**
 * Result of matching requirements between two evaluations.
 */
export interface MatchResult {
  /** Paired requirements with their match metadata */
  matched: MatchPair[];
  /** Requirements only in the old evaluation (unmatched) */
  unmatchedOld: Record<string, unknown>[];
  /** Requirements only in the new evaluation (unmatched) */
  unmatchedNew: Record<string, unknown>[];
}

/**
 * A single matched pair of requirements.
 */
export interface MatchPair {
  /** The requirement from the old evaluation */
  oldReq: Record<string, unknown>;
  /** The requirement from the new evaluation */
  newReq: Record<string, unknown>;
  /** Name of the strategy that produced this match */
  strategy: string;
  /** Confidence score for the match (0.0 - 1.0) */
  confidence: number;
  /** Relationship type for delta matching: 'primary' (code source) or 'related' (informational) */
  relationship?: 'primary' | 'related';
}

/**
 * A pluggable strategy for matching requirements between evaluations.
 */
export interface MatchStrategy {
  /** Unique name for this strategy */
  name: string;
  /** Match old requirements against new requirements */
  match(oldReqs: Record<string, unknown>[], newReqs: Record<string, unknown>[]): MatchResult;
}
