package matching

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

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

// Match pairs requirements by exact ID. An id carried by several entries names one
// requirement reported several times, so pairOccurrences pairs those among
// themselves rather than abandoning them as ambiguous.
func (s *ExactIDStrategy) Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult {
	result := MatchResult{}

	oldByID := buildIDIndex(oldReqs)
	newByID := buildIDIndex(newReqs)

	// Document order, one id at a time: the result's order must not depend on map
	// iteration, because the TypeScript half emits the same one.
	pairedWith := make(map[int]int, len(oldReqs))
	pairedNew := make(map[int]bool, len(newReqs))
	seen := make(map[string]bool, len(oldByID))
	for _, oldReq := range oldReqs {
		id := oldReq.ID
		if seen[id] {
			continue
		}
		seen[id] = true
		pairs, _, _ := pairOccurrences(oldByID[id], newByID[id], oldReqs, newReqs)
		for _, p := range pairs {
			pairedWith[p[0]] = p[1]
			pairedNew[p[1]] = true
		}
	}

	for i, oldReq := range oldReqs {
		newIdx, ok := pairedWith[i]
		if !ok {
			result.UnmatchedOld = append(result.UnmatchedOld, oldReq)
			continue
		}
		result.Matched = append(result.Matched, MatchPair{
			OldReq:     oldReq,
			NewReq:     newReqs[newIdx],
			Strategy:   exactIDStrategyName,
			Confidence: 1.0,
		})
	}

	for i, req := range newReqs {
		if !pairedNew[i] {
			result.UnmatchedNew = append(result.UnmatchedNew, req)
		}
	}

	return result
}
