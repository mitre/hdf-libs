package matching

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

// SRGDeterministicStrategy matches requirements by exact tags.gtitle (SRG-OS ID).
// This is Tier 1 of the delta matching pipeline.
//
// For each gtitle shared between old and new:
//   - 1 old + 1 new → single MatchPair (confidence 1.0, relationship "primary")
//   - 1 new + N old → N MatchPairs (first old "primary", rest "related")
//   - N new + 1 old → N MatchPairs (first new "primary", rest "related")
//   - N:M (both > 1) → skip, leave for fallback strategies
type SRGDeterministicStrategy struct{}

// NewSRGDeterministicStrategy creates a new SRG deterministic matching strategy.
func NewSRGDeterministicStrategy() *SRGDeterministicStrategy {
	return &SRGDeterministicStrategy{}
}

// Name returns the strategy name.
func (s *SRGDeterministicStrategy) Name() string {
	return "srgDeterministic"
}

// extractGtitle extracts tags.gtitle from a requirement.
// Returns "" if missing or not a string.
func extractGtitle(req hdf.EvaluatedRequirement) string {
	if req.Tags == nil {
		return ""
	}
	val, ok := req.Tags["gtitle"]
	if !ok {
		return ""
	}
	str, ok := val.(string)
	if !ok || str == "" {
		return ""
	}
	return str
}

// Match implements the Strategy interface.
func (s *SRGDeterministicStrategy) Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult {
	result := MatchResult{}

	// Build gtitle → indices for old
	oldGtitleMap := make(map[string][]int)
	for i, req := range oldReqs {
		g := extractGtitle(req)
		if g != "" {
			oldGtitleMap[g] = append(oldGtitleMap[g], i)
		}
	}

	// Build gtitle → indices for new
	newGtitleMap := make(map[string][]int)
	for i, req := range newReqs {
		g := extractGtitle(req)
		if g != "" {
			newGtitleMap[g] = append(newGtitleMap[g], i)
		}
	}

	matchedOldIndices := make(map[int]bool)
	matchedNewIndices := make(map[int]bool)
	claimedOldIndices := make(map[int]bool)

	for gtitle, newIdxList := range newGtitleMap {
		oldIdxList, ok := oldGtitleMap[gtitle]
		if !ok || len(oldIdxList) == 0 {
			continue
		}

		nc := len(newIdxList)
		oc := len(oldIdxList)

		// N:M ambiguous — skip
		if nc > 1 && oc > 1 {
			continue
		}

		// Create match pairs
		for _, ni := range newIdxList {
			primaryOldSet := false
			for _, oi := range oldIdxList {
				var relationship string
				if oc == 1 {
					// 1 old, possibly multiple new → claim tracking
					if claimedOldIndices[oi] {
						relationship = "related"
					} else {
						relationship = "primary"
						claimedOldIndices[oi] = true
					}
				} else {
					// Multiple old, 1 new → first old is primary
					if primaryOldSet {
						relationship = "related"
					} else {
						relationship = "primary"
						primaryOldSet = true
					}
				}

				result.Matched = append(result.Matched, MatchPair{
					OldReq:       oldReqs[oi],
					NewReq:       newReqs[ni],
					Strategy:     "srgDeterministic",
					Confidence:   1.0,
					Relationship: relationship,
				})
				matchedOldIndices[oi] = true
			}
			matchedNewIndices[ni] = true
		}
	}

	// Collect unmatched
	for i, req := range oldReqs {
		if !matchedOldIndices[i] {
			result.UnmatchedOld = append(result.UnmatchedOld, req)
		}
	}
	for i, req := range newReqs {
		if !matchedNewIndices[i] {
			result.UnmatchedNew = append(result.UnmatchedNew, req)
		}
	}

	return result
}
