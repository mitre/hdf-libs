package matching

import (
	"regexp"
	"sort"
	"strings"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// defaultMinConfidence is the default minimum Jaccard similarity threshold.
const defaultMinConfidence = 0.6

// stopWords contains common English stop words to exclude from tokenization.
var stopWords = map[string]bool{
	"a": true, "an": true, "the": true, "is": true, "are": true,
	"was": true, "were": true, "be": true, "been": true, "being": true,
	"have": true, "has": true, "had": true, "do": true, "does": true,
	"did": true, "will": true, "would": true, "could": true,
	"should": true, "may": true, "might": true, "shall": true, "can": true,
	"to": true, "of": true, "in": true, "for": true,
	"on": true, "with": true, "at": true, "by": true, "from": true,
	"as": true, "into": true, "through": true, "during": true,
	"before": true, "after": true, "above": true, "below": true,
	"between": true, "out": true, "off": true, "over": true,
	"under": true, "again": true, "further": true, "then": true,
	"once": true, "and": true, "but": true, "or": true, "nor": true,
	"not": true, "no": true, "so": true, "if": true, "it": true,
	"its": true, "that": true, "this": true, "these": true, "those": true,
	"each": true, "every": true, "all": true, "both": true, "few": true,
	"more": true, "most": true, "other": true, "some": true,
	"such": true, "than": true, "too": true, "very": true, "just": true,
	"about": true,
}

// splitRegex splits on non-alphanumeric characters.
var splitRegex = regexp.MustCompile(`[^a-z0-9]+`)

// Tokenize splits a title string into a set of meaningful tokens.
// It lowercases the string, splits on non-alphanumeric characters,
// filters out stop words and tokens with length <= 2, and returns unique tokens.
func Tokenize(text string) []string {
	if text == "" {
		return nil
	}

	lower := strings.ToLower(text)
	parts := splitRegex.Split(lower, -1)

	seen := make(map[string]bool)
	var result []string
	for _, token := range parts {
		if len(token) <= 2 {
			continue
		}
		if stopWords[token] {
			continue
		}
		if !seen[token] {
			seen[token] = true
			result = append(result, token)
		}
	}
	return result
}

// JaccardSimilarity computes the Jaccard similarity between two sets.
// Returns |intersection| / |union|, or 0 if both sets are empty.
func JaccardSimilarity(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0.0
	}

	// Iterate over the smaller set for efficiency
	smaller, larger := a, b
	if len(a) > len(b) {
		smaller, larger = b, a
	}

	intersectionSize := 0
	for item := range smaller {
		if larger[item] {
			intersectionSize++
		}
	}

	unionSize := len(a) + len(b) - intersectionSize
	if unionSize == 0 {
		return 0.0
	}

	return float64(intersectionSize) / float64(unionSize)
}

// tokenSet converts a slice of tokens to a set (map[string]bool).
func tokenSet(tokens []string) map[string]bool {
	s := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		s[t] = true
	}
	return s
}

// FuzzyTitleStrategy matches requirements by token-based Jaccard similarity on titles.
type FuzzyTitleStrategy struct {
	threshold float64
}

// NewFuzzyTitleStrategy creates a new fuzzy title matching strategy.
// If minConfidence is 0 or negative, the default threshold of 0.6 is used.
func NewFuzzyTitleStrategy(minConfidence float64) *FuzzyTitleStrategy {
	if minConfidence <= 0 {
		minConfidence = defaultMinConfidence
	}
	return &FuzzyTitleStrategy{threshold: minConfidence}
}

// Name returns the strategy name.
func (s *FuzzyTitleStrategy) Name() string {
	return "fuzzyTitle"
}

type candidate struct {
	oldIdx     int
	newIdx     int
	similarity float64
}

// Match matches requirements by fuzzy title similarity using greedy best-match.
func (s *FuzzyTitleStrategy) Match(oldReqs, newReqs []hdf.EvaluatedRequirement) MatchResult {
	result := MatchResult{}

	// Pre-tokenize all titles
	type indexedTokens struct {
		idx    int
		tokens map[string]bool
	}

	var oldTokens []indexedTokens
	for i, req := range oldReqs {
		if req.Title != nil && *req.Title != "" {
			tokens := Tokenize(*req.Title)
			if len(tokens) > 0 {
				oldTokens = append(oldTokens, indexedTokens{idx: i, tokens: tokenSet(tokens)})
			}
		}
	}

	var newTokens []indexedTokens
	for i, req := range newReqs {
		if req.Title != nil && *req.Title != "" {
			tokens := Tokenize(*req.Title)
			if len(tokens) > 0 {
				newTokens = append(newTokens, indexedTokens{idx: i, tokens: tokenSet(tokens)})
			}
		}
	}

	// Track matched indices
	matchedOldIndices := make(map[int]bool)
	matchedNewIndices := make(map[int]bool)

	// Build all potential matches with similarity scores
	var candidates []candidate
	for _, old := range oldTokens {
		for _, nw := range newTokens {
			sim := JaccardSimilarity(old.tokens, nw.tokens)
			if sim >= s.threshold {
				candidates = append(candidates, candidate{
					oldIdx:     old.idx,
					newIdx:     nw.idx,
					similarity: sim,
				})
			}
		}
	}

	// Sort by similarity descending (greedy best-match)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].similarity > candidates[j].similarity
	})

	// Greedily assign matches
	for _, c := range candidates {
		if matchedOldIndices[c.oldIdx] || matchedNewIndices[c.newIdx] {
			continue
		}

		result.Matched = append(result.Matched, MatchPair{
			OldReq:     oldReqs[c.oldIdx],
			NewReq:     newReqs[c.newIdx],
			Strategy:   "fuzzyTitle",
			Confidence: c.similarity,
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
