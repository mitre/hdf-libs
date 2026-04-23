package matching

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"

// exactIDStrategyName is the canonical name for the exact ID matching strategy.
const exactIDStrategyName = "exactId"

// ExactIDStrategy matches requirements by exact string equality on the ID field.
type ExactIDStrategy struct{}

// NewExactIDStrategy creates a new exact ID matching strategy.
func NewExactIDStrategy() *ExactIDStrategy {
	return &ExactIDStrategy{}
}

// Name returns the strategy name.
func (s *ExactIDStrategy) Name() string {
	return exactIDStrategyName
}

// Match matches old requirements against new requirements by exact ID.
// Duplicate IDs on either side are treated as ambiguous and left unmatched.
func (s *ExactIDStrategy) Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult {
	result := MatchResult{}

	newByID, duplicateNewIDs := buildUniqueIDIndex(newReqs)
	_, duplicateOldIDs := buildUniqueIDIndex(oldReqs)

	// Track which new reqs have been matched
	matchedNewIDs := make(map[string]bool)

	// Match old requirements against new by ID (skip duplicate old IDs)
	for _, oldReq := range oldReqs {
		id := oldReq.ID
		if duplicateOldIDs[id] {
			result.UnmatchedOld = append(result.UnmatchedOld, oldReq)
			continue
		}

		if newIdx, ok := newByID[id]; ok {
			result.Matched = append(result.Matched, MatchPair{
				OldReq:     oldReq,
				NewReq:     newReqs[newIdx],
				Strategy:   exactIDStrategyName,
				Confidence: 1.0,
			})
			matchedNewIDs[id] = true
		} else {
			result.UnmatchedOld = append(result.UnmatchedOld, oldReq)
		}
	}

	// Collect unmatched new requirements (including all duplicates)
	for _, req := range newReqs {
		id := req.ID
		if duplicateNewIDs[id] || !matchedNewIDs[id] {
			result.UnmatchedNew = append(result.UnmatchedNew, req)
		}
	}

	return result
}
