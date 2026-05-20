package matching

import (
	"sort"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// defaultAcceptThreshold is the max normalized Levenshtein distance to accept.
const defaultAcceptThreshold = 0.45

// complianceModals marks the start of compliance statements in STIG titles.
var complianceModals = map[string]bool{
	"must": true, "will": true, "shall": true,
	"should": true, "may": true, "needs": true,
}

// VendorFuzzyTitleStrategy matches requirements by prefix-stripped Levenshtein distance.
// This is Tier 3 of the delta matching pipeline.
type VendorFuzzyTitleStrategy struct {
	threshold float64
}

// NewVendorFuzzyTitleStrategy creates a new vendor fuzzy title strategy.
// If acceptThreshold is 0 or negative, the default of 0.45 is used.
func NewVendorFuzzyTitleStrategy(acceptThreshold float64) *VendorFuzzyTitleStrategy {
	if acceptThreshold <= 0 {
		acceptThreshold = defaultAcceptThreshold
	}
	return &VendorFuzzyTitleStrategy{threshold: acceptThreshold}
}

// Name returns the strategy name.
func (s *VendorFuzzyTitleStrategy) Name() string {
	return "vendorFuzzyTitle"
}

// LevenshteinDistance computes the Levenshtein edit distance between two strings.
func LevenshteinDistance(a, b string) int {
	aRunes := []rune(a)
	bRunes := []rune(b)
	m := len(aRunes)
	n := len(bRunes)
	if m == 0 {
		return n
	}
	if n == 0 {
		return m
	}

	prev := make([]int, n+1)
	curr := make([]int, n+1)
	for j := 0; j <= n; j++ {
		prev[j] = j
	}

	for i := 1; i <= m; i++ {
		curr[0] = i
		for j := 1; j <= n; j++ {
			cost := 1
			if aRunes[i-1] == bRunes[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			curr[j] = min(del, min(ins, sub))
		}
		prev, curr = curr, prev
	}

	return prev[n]
}

// NormalizedLevenshtein returns normalized edit distance (0.0 = identical, 1.0 = completely different).
func NormalizedLevenshtein(a, b string) float64 {
	maxLen := max(len(a), len(b))
	if maxLen == 0 {
		return 0.0
	}
	return float64(LevenshteinDistance(a, b)) / float64(maxLen)
}

// tokensBeforeModal extracts tokens before the first modal verb.
func tokensBeforeModal(title string) []string {
	tokens := strings.Fields(title)
	for i, t := range tokens {
		if complianceModals[strings.ToLower(t)] {
			return tokens[:i]
		}
	}
	return tokens
}

// AutoDetectPrefix discovers the dominant leading-token prefix in a corpus.
func AutoDetectPrefix(titles []string, threshold float64) string {
	if len(titles) == 0 {
		return ""
	}
	if threshold <= 0 {
		threshold = 0.5
	}

	leading := make([][]string, len(titles))
	maxLen := 0
	for i, t := range titles {
		leading[i] = tokensBeforeModal(t)
		if len(leading[i]) > maxLen {
			maxLen = len(leading[i])
		}
	}

	for n := maxLen; n > 0; n-- {
		counts := make(map[string]int)
		for _, l := range leading {
			if len(l) >= n {
				key := strings.Join(l[:n], " ")
				counts[key]++
			}
		}
		bestKey := ""
		bestCount := 0
		for key, count := range counts {
			if count > bestCount {
				bestKey = key
				bestCount = count
			}
		}
		if float64(bestCount)/float64(len(titles)) > threshold {
			return bestKey
		}
	}
	return ""
}

// NormalizeTitle strips a detected vendor prefix from a title.
func NormalizeTitle(title, prefix string) string {
	if prefix == "" {
		return title
	}
	if title == prefix {
		return ""
	}
	if strings.HasPrefix(title, prefix+" ") {
		return title[len(prefix)+1:]
	}
	return title
}

type vendorCandidate struct {
	oldIdx   int
	newIdx   int
	distance float64
}

// Match implements the Strategy interface.
func (s *VendorFuzzyTitleStrategy) Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult {
	result := MatchResult{}

	// Collect titles for prefix detection
	var oldTitles, newTitles []string
	for _, req := range oldReqs {
		if req.Title != nil && *req.Title != "" {
			oldTitles = append(oldTitles, *req.Title)
		}
	}
	for _, req := range newReqs {
		if req.Title != nil && *req.Title != "" {
			newTitles = append(newTitles, *req.Title)
		}
	}
	oldPrefix := AutoDetectPrefix(oldTitles, 0.5)
	newPrefix := AutoDetectPrefix(newTitles, 0.5)

	// Build normalized title lists
	type indexedTitle struct {
		idx        int
		normalized string
	}
	var oldNorm, newNorm []indexedTitle
	for i, req := range oldReqs {
		if req.Title != nil && *req.Title != "" {
			oldNorm = append(oldNorm, indexedTitle{idx: i, normalized: NormalizeTitle(*req.Title, oldPrefix)})
		}
	}
	for i, req := range newReqs {
		if req.Title != nil && *req.Title != "" {
			newNorm = append(newNorm, indexedTitle{idx: i, normalized: NormalizeTitle(*req.Title, newPrefix)})
		}
	}

	// Compute all pairwise distances
	var candidates []vendorCandidate
	for _, old := range oldNorm {
		if old.normalized == "" {
			continue
		}
		for _, nw := range newNorm {
			if nw.normalized == "" {
				continue
			}
			dist := NormalizedLevenshtein(old.normalized, nw.normalized)
			if dist < s.threshold {
				candidates = append(candidates, vendorCandidate{
					oldIdx:   old.idx,
					newIdx:   nw.idx,
					distance: dist,
				})
			}
		}
	}

	// Sort by distance ascending
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].distance < candidates[j].distance
	})

	// Greedy assignment
	matchedOldIndices := make(map[int]bool)
	matchedNewIndices := make(map[int]bool)

	for _, c := range candidates {
		if matchedOldIndices[c.oldIdx] || matchedNewIndices[c.newIdx] {
			continue
		}

		result.Matched = append(result.Matched, MatchPair{
			OldReq:       oldReqs[c.oldIdx],
			NewReq:       newReqs[c.newIdx],
			Strategy:     "vendorFuzzyTitle",
			Confidence:   1.0 - c.distance,
			Relationship: "primary",
		})
		matchedOldIndices[c.oldIdx] = true
		matchedNewIndices[c.newIdx] = true
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
