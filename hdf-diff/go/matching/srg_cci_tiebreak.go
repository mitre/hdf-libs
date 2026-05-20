package matching

import (
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// Composite score weights matching SAF CLI's Tier 2.
const (
	cciWeight   = 0.7
	titleWeight = 0.3
)

// SRGCCITiebreakStrategy handles ambiguous SRG matches using CCI Jaccard + token Jaccard.
// This is Tier 2 of the delta matching pipeline.
//
// Only activates for gtitle groups with multiple candidates (>1 old or >1 new).
// 1:1 matches belong to srgDeterministic (Tier 1).
type SRGCCITiebreakStrategy struct{}

// NewSRGCCITiebreakStrategy creates a new SRG CCI tiebreak matching strategy.
func NewSRGCCITiebreakStrategy() *SRGCCITiebreakStrategy {
	return &SRGCCITiebreakStrategy{}
}

// Name returns the strategy name.
func (s *SRGCCITiebreakStrategy) Name() string {
	return "srgCciTiebreak"
}

// extractCCISet extracts CCI identifiers from Tags["cci"] as a set.
// Handles both []any (from JSON unmarshal) and []string (from typed converters).
func extractCCISet(req hdf.EvaluatedRequirement) map[string]bool {
	result := make(map[string]bool)
	if req.Tags == nil {
		return result
	}
	cciVal, ok := req.Tags["cci"]
	if !ok {
		return result
	}
	switch v := cciVal.(type) {
	case []any:
		for _, c := range v {
			if str, ok := c.(string); ok {
				result[str] = true
			}
		}
	case []string:
		for _, c := range v {
			result[c] = true
		}
	}
	return result
}

// cciJaccardSimilarity computes Jaccard similarity between two CCI sets.
func cciJaccardSimilarity(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	intersectionSize := 0
	for k := range a {
		if b[k] {
			intersectionSize++
		}
	}
	unionSize := len(a) + len(b) - intersectionSize
	if unionSize == 0 {
		return 0
	}
	return float64(intersectionSize) / float64(unionSize)
}

// simpleTokenJaccard computes a simple whitespace-split token Jaccard similarity.
func simpleTokenJaccard(a, b string) float64 {
	ta := simpleTokenize(a)
	tb := simpleTokenize(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	intersectionSize := 0
	for k := range ta {
		if tb[k] {
			intersectionSize++
		}
	}
	unionSize := len(ta) + len(tb) - intersectionSize
	if unionSize == 0 {
		return 0
	}
	return float64(intersectionSize) / float64(unionSize)
}

// simpleTokenize splits on whitespace, lowercases, and returns unique tokens.
func simpleTokenize(s string) map[string]bool {
	result := make(map[string]bool)
	for _, t := range strings.Fields(strings.ToLower(s)) {
		if len(t) > 0 {
			result[t] = true
		}
	}
	return result
}

// safeTitle returns the title or empty string.
func safeTitle(req hdf.EvaluatedRequirement) string {
	if req.Title == nil {
		return ""
	}
	return *req.Title
}

// Match implements the Strategy interface.
func (s *SRGCCITiebreakStrategy) Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult {
	result := MatchResult{}

	// Build gtitle → indices
	oldGtitleMap := make(map[string][]int)
	for i, req := range oldReqs {
		g := extractGtitle(req)
		if g != "" {
			oldGtitleMap[g] = append(oldGtitleMap[g], i)
		}
	}

	newGtitleMap := make(map[string][]int)
	for i, req := range newReqs {
		g := extractGtitle(req)
		if g != "" {
			newGtitleMap[g] = append(newGtitleMap[g], i)
		}
	}

	matchedOldIndices := make(map[int]bool)
	matchedNewIndices := make(map[int]bool)

	for gtitle, newIdxList := range newGtitleMap {
		oldIdxList, ok := oldGtitleMap[gtitle]
		if !ok || len(oldIdxList) == 0 {
			continue
		}

		nc := len(newIdxList)
		oc := len(oldIdxList)

		// Only handle ambiguous cases (at least one side > 1)
		if nc == 1 && oc == 1 {
			continue
		}

		// Greedy matching: process each new req, find best old candidate
		for _, ni := range newIdxList {
			if matchedNewIndices[ni] {
				continue
			}

			newCcis := extractCCISet(newReqs[ni])
			newTitle := safeTitle(newReqs[ni])

			bestIdx := -1
			bestComposite := -1.0
			bestCci := 0.0
			bestIsUnclaimed := false

			for _, oi := range oldIdxList {
				oldCcis := extractCCISet(oldReqs[oi])
				oldTitle := safeTitle(oldReqs[oi])

				cci := cciJaccardSimilarity(newCcis, oldCcis)
				title := simpleTokenJaccard(newTitle, oldTitle)
				composite := cciWeight*cci + titleWeight*title
				isUnclaimed := !matchedOldIndices[oi]

				if bestIdx == -1 ||
					(isUnclaimed && !bestIsUnclaimed) ||
					(isUnclaimed == bestIsUnclaimed && composite > bestComposite) {
					bestIdx = oi
					bestComposite = composite
					bestCci = cci
					bestIsUnclaimed = isUnclaimed
				}
			}

			if bestIdx >= 0 && bestIdx < len(oldReqs) {
				relationship := "primary"
				if matchedOldIndices[bestIdx] {
					relationship = "related"
				}

				confidence := bestCci
				if confidence < 0 {
					confidence = 0
				}

				result.Matched = append(result.Matched, MatchPair{
					OldReq:       oldReqs[bestIdx],
					NewReq:       newReqs[ni],
					Strategy:     "srgCciTiebreak",
					Confidence:   confidence,
					Relationship: relationship,
				})
				matchedOldIndices[bestIdx] = true
				matchedNewIndices[ni] = true
			}
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
