package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Tokenize unit tests ---

func TestTokenize_LowercaseAndSplit(t *testing.T) {
	tokens := Tokenize("Ensure SSH Root Login")
	assert.Contains(t, tokens, "ensure")
	assert.Contains(t, tokens, "ssh")
	assert.Contains(t, tokens, "root")
	assert.Contains(t, tokens, "login")
}

func TestTokenize_SplitOnPunctuation(t *testing.T) {
	tokens := Tokenize("root-login/access")
	assert.Contains(t, tokens, "root")
	assert.Contains(t, tokens, "login")
	assert.Contains(t, tokens, "access")
}

func TestTokenize_RemoveStopWords(t *testing.T) {
	tokens := Tokenize("the quick brown fox is a test")
	assert.NotContains(t, tokens, "the")
	assert.NotContains(t, tokens, "is")
	assert.NotContains(t, tokens, "a")
	assert.Contains(t, tokens, "quick")
	assert.Contains(t, tokens, "brown")
	assert.Contains(t, tokens, "fox")
}

func TestTokenize_EmptyString(t *testing.T) {
	tokens := Tokenize("")
	assert.Len(t, tokens, 0)
}

func TestTokenize_OnlyStopWords(t *testing.T) {
	tokens := Tokenize("the a an is")
	assert.Len(t, tokens, 0)
}

func TestTokenize_Deduplication(t *testing.T) {
	tokens := Tokenize("ssh ssh ssh login")
	// Set semantics: unique tokens only
	count := 0
	for _, tok := range tokens {
		if tok == "ssh" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestTokenize_FilterShortTokens(t *testing.T) {
	// Tokens <= 2 chars should be filtered (except stop words are already filtered)
	// The TS implementation filters on length > 0 and stop words
	// The Go implementation should also filter tokens with length <= 2
	tokens := Tokenize("ab cd ensure")
	assert.NotContains(t, tokens, "ab")
	assert.NotContains(t, tokens, "cd")
	assert.Contains(t, tokens, "ensure")
}

// --- JaccardSimilarity unit tests ---

func TestJaccardSimilarity_IdenticalSets(t *testing.T) {
	a := mapSet("ssh", "root", "login")
	b := mapSet("ssh", "root", "login")
	assert.Equal(t, 1.0, JaccardSimilarity(a, b))
}

func TestJaccardSimilarity_DisjointSets(t *testing.T) {
	a := mapSet("ssh", "root", "login")
	b := mapSet("ntp", "time", "sync")
	assert.Equal(t, 0.0, JaccardSimilarity(a, b))
}

func TestJaccardSimilarity_PartialOverlap(t *testing.T) {
	a := mapSet("ssh", "root", "login", "disabled")
	b := mapSet("ssh", "root", "login", "must", "disabled")
	// intersection = {ssh, root, login, disabled} = 4
	// union = {ssh, root, login, disabled, must} = 5
	assert.InDelta(t, 0.8, JaccardSimilarity(a, b), 0.00001)
}

func TestJaccardSimilarity_BothEmpty(t *testing.T) {
	assert.Equal(t, 0.0, JaccardSimilarity(mapSet(), mapSet()))
}

func TestJaccardSimilarity_OneEmpty(t *testing.T) {
	assert.Equal(t, 0.0, JaccardSimilarity(mapSet("a"), mapSet()))
}

// --- FuzzyTitle strategy tests ---

func TestFuzzyTitleStrategy_Name(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	assert.Equal(t, "fuzzyTitle", s.Name())
}

func TestFuzzyTitleStrategy_MatchSimilarTitles(t *testing.T) {
	s := NewFuzzyTitleStrategy(0) // default threshold
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr("SSH root login must be disabled"), Impact: 0.7},
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
	assert.Equal(t, "RHEL-001", result.Matched[0].NewReq.ID)
	assert.GreaterOrEqual(t, result.Matched[0].Confidence, 0.6)
	assert.Equal(t, "fuzzyTitle", result.Matched[0].Strategy)
}

func TestFuzzyTitleStrategy_DissimilarTitles(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr("Configure NTP time synchronization"), Impact: 0.7},
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestFuzzyTitleStrategy_CustomThreshold(t *testing.T) {
	s := NewFuzzyTitleStrategy(0.9)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr("SSH root login must be disabled"), Impact: 0.7},
	}

	result := s.Match(oldReqs, newReqs)

	// With 0.9 threshold, slightly different titles should not match
	assert.Len(t, result.Matched, 0)
}

func TestFuzzyTitleStrategy_GreedyBestMatch(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr("SSH root login must be disabled"), Impact: 0.7},
		{ID: "RHEL-002", Title: strPtr("SSH protocol version must be 2"), Impact: 0.5},
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "RHEL-001", result.Matched[0].NewReq.ID)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestFuzzyTitleStrategy_NoTitle(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "RHEL-001", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestFuzzyTitleStrategy_EmptyTitles(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr(""), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr(""), Impact: 0.7},
	}

	result := s.Match(oldReqs, newReqs)

	// Empty titles produce empty token sets -> similarity 0
	assert.Len(t, result.Matched, 0)
}

func TestFuzzyTitleStrategy_IdenticalTitles(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, 1.0, result.Matched[0].Confidence)
}

func TestFuzzyTitleStrategy_GreedySkipsAlreadyMatched(t *testing.T) {
	s := NewFuzzyTitleStrategy(0.3) // low threshold
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "1", Title: strPtr("SSH root login configuration check"), Impact: 0.7},
		{ID: "2", Title: strPtr("SSH root login setting verification"), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "A", Title: strPtr("SSH root login configuration check"), Impact: 0.7},
	}

	result := s.Match(oldReqs, newReqs)

	// One match (best scoring pair), one unmatched old, zero unmatched new
	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestFuzzyTitleStrategy_MultipleGreedyMatches(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
		{ID: "V-002", Title: strPtr("NTP time synchronization configured correctly"), Impact: 0.5},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr("SSH root login must be disabled"), Impact: 0.7},
		{ID: "RHEL-002", Title: strPtr("NTP time synchronization configured properly"), Impact: 0.5},
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 2)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestFuzzyTitleStrategy_BothEmpty(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	result := s.Match(nil, nil)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestFuzzyTitleStrategy_NilTitle(t *testing.T) {
	s := NewFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7, Title: nil}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "RHEL-001", Impact: 0.7, Title: nil}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

// --- JaccardSimilarity: a larger than b (swap branch) ---

func TestJaccardSimilarity_ALargerThanB(t *testing.T) {
	// a has more elements, b is smaller -- ensures the swap optimization is exercised
	a := mapSet("ssh", "root", "login", "disabled", "config", "setting")
	b := mapSet("ssh", "root")
	// intersection = {ssh, root} = 2
	// union = {ssh, root, login, disabled, config, setting} = 6
	expected := 2.0 / 6.0
	assert.InDelta(t, expected, JaccardSimilarity(a, b), 0.00001)
}

func TestJaccardSimilarity_BLargerThanA(t *testing.T) {
	a := mapSet("ssh", "root")
	b := mapSet("ssh", "root", "login", "disabled", "config", "setting")
	expected := 2.0 / 6.0
	assert.InDelta(t, expected, JaccardSimilarity(a, b), 0.00001)
}

func TestJaccardSimilarity_SingleElement(t *testing.T) {
	a := mapSet("ssh")
	b := mapSet("ssh")
	assert.Equal(t, 1.0, JaccardSimilarity(a, b))
}

// helper to create a set (as a map[string]bool for Jaccard tests).
func mapSet(items ...string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
