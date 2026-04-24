package matching

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

// CCIMatchStrategy matches requirements by shared CCI identifiers in tags.
type CCIMatchStrategy struct{}

// NewCCIMatchStrategy creates a new CCI-based matching strategy.
func NewCCIMatchStrategy() *CCIMatchStrategy {
	return &CCIMatchStrategy{}
}

// Name returns the strategy name.
func (s *CCIMatchStrategy) Name() string {
	return "cciMatch"
}

// extractCCIs extracts CCI identifiers from a requirement's Tags["cci"] field.
// The cci field is expected to be []any with string elements.
func extractCCIs(req hdf.EvaluatedRequirement) []string {
	if req.Tags == nil {
		return nil
	}

	cciVal, ok := req.Tags["cci"]
	if !ok {
		return nil
	}

	cciSlice, ok := cciVal.([]any)
	if !ok {
		return nil
	}

	result := make([]string, 0, len(cciSlice))
	for _, c := range cciSlice {
		if s, ok := c.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// Match matches requirements that share unambiguous CCI identifiers.
// Only produces a match when exactly one old requirement and exactly one new
// requirement share a given CCI. Confidence is 0.8 for unambiguous matches.
func (s *CCIMatchStrategy) Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult {
	result := MatchResult{}

	// Build CCI -> requirement indices for old and new
	oldCCIMap := make(map[string][]int)
	for i, req := range oldReqs {
		for _, cci := range extractCCIs(req) {
			oldCCIMap[cci] = append(oldCCIMap[cci], i)
		}
	}

	newCCIMap := make(map[string][]int)
	for i, req := range newReqs {
		for _, cci := range extractCCIs(req) {
			newCCIMap[cci] = append(newCCIMap[cci], i)
		}
	}

	// Track which indices have been matched
	matchedOldIndices := make(map[int]bool)
	matchedNewIndices := make(map[int]bool)

	// Collect all CCIs from both maps
	allCCIs := make(map[string]bool)
	for cci := range oldCCIMap {
		allCCIs[cci] = true
	}
	for cci := range newCCIMap {
		allCCIs[cci] = true
	}

	// Find unambiguous CCI matches: exactly 1 old and 1 new share the CCI
	for cci := range allCCIs {
		oldIndices := oldCCIMap[cci] // nil slice if not present, len=0
		newIndices := newCCIMap[cci]

		if len(oldIndices) != 1 || len(newIndices) != 1 {
			// Ambiguous or one-sided — skip
			continue
		}

		oldIdx := oldIndices[0]
		newIdx := newIndices[0]

		// Don't double-match
		if matchedOldIndices[oldIdx] || matchedNewIndices[newIdx] {
			continue
		}

		result.Matched = append(result.Matched, MatchPair{
			OldReq:     oldReqs[oldIdx],
			NewReq:     newReqs[newIdx],
			Strategy:   "cciMatch",
			Confidence: 0.8,
		})
		matchedOldIndices[oldIdx] = true
		matchedNewIndices[newIdx] = true
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
