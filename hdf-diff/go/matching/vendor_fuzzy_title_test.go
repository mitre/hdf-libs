package matching

import (
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLevenshteinDistance_BoundsOverlongInput: pathological over-cap inputs are
// not run through the O(m*n) DP — they return the trivial upper bound max(m,n).
// Realistic-length titles keep their exact distance.
func TestLevenshteinDistance_BoundsOverlongInput(t *testing.T) {
	a := strings.Repeat("x", maxLevenshteinRunes+1000)
	b := a + strings.Repeat("y", 100) // exact edit distance is 100
	got := LevenshteinDistance(a, b)
	assert.Equal(t, len([]rune(b)), got,
		"over-cap inputs return max(m,n), not the exact distance")

	// A boundary-length pair (exactly at the cap) is still computed exactly.
	c := strings.Repeat("x", maxLevenshteinRunes)
	d := strings.Repeat("x", maxLevenshteinRunes-1) + "y"
	assert.Equal(t, 1, LevenshteinDistance(c, d), "at-cap inputs keep the exact distance")

	// Normal titles are unaffected.
	assert.Equal(t, 3, LevenshteinDistance("kitten", "sitting"))
}

func TestLevenshteinDistance(t *testing.T) {
	assert.Equal(t, 0, LevenshteinDistance("abc", "abc"))
	assert.Equal(t, 3, LevenshteinDistance("", "abc"))
	assert.Equal(t, 3, LevenshteinDistance("abc", ""))
	assert.Equal(t, 0, LevenshteinDistance("", ""))
	assert.Equal(t, 3, LevenshteinDistance("kitten", "sitting"))
	assert.Equal(t, 3, LevenshteinDistance("Saturday", "Sunday"))
	assert.Equal(t, 1, LevenshteinDistance("a", "b"))
}

func TestNormalizedLevenshtein(t *testing.T) {
	assert.Equal(t, 0.0, NormalizedLevenshtein("abc", "abc"))
	assert.Equal(t, 0.0, NormalizedLevenshtein("", ""))
	assert.Equal(t, 1.0, NormalizedLevenshtein("a", "b"))
	dist := NormalizedLevenshtein("kitten", "sitting")
	assert.Greater(t, dist, 0.0)
	assert.Less(t, dist, 1.0)
}

func TestAutoDetectPrefix(t *testing.T) {
	t.Run("dominant prefix", func(t *testing.T) {
		titles := []string{
			"RHEL 9 must be supported.",
			"RHEL 9 must check GPG signatures.",
			"RHEL 9 must disable audit.",
			"Ubuntu 22 must use TLS.",
		}
		assert.Equal(t, "RHEL 9", AutoDetectPrefix(titles, 0.5))
	})

	t.Run("no dominant prefix", func(t *testing.T) {
		titles := []string{
			"Ensure password complexity is set.",
			"Verify SSH is configured.",
			"Check file permissions.",
			"Audit log rotation.",
		}
		assert.Equal(t, "", AutoDetectPrefix(titles, 0.5))
	})

	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", AutoDetectPrefix(nil, 0.5))
	})

	t.Run("stops before modal", func(t *testing.T) {
		titles := []string{
			"The Apache web server must be configured.",
			"The Apache web server must limit connections.",
			"The Apache web server must use TLS.",
		}
		assert.Equal(t, "The Apache web server", AutoDetectPrefix(titles, 0.5))
	})
}

func TestNormalizeTitle(t *testing.T) {
	assert.Equal(t, "must be supported.", NormalizeTitle("RHEL 9 must be supported.", "RHEL 9"))
	assert.Equal(t, "must be supported.", NormalizeTitle("must be supported.", ""))
	assert.Equal(t, "Ubuntu must use RHEL 9 tools.", NormalizeTitle("Ubuntu must use RHEL 9 tools.", "RHEL 9"))
	assert.Equal(t, "", NormalizeTitle("RHEL 9", "RHEL 9"))
}

func TestVendorFuzzyTitleStrategy_Name(t *testing.T) {
	s := NewVendorFuzzyTitleStrategy(0)
	assert.Equal(t, "vendorFuzzyTitle", s.Name())
}

func TestVendorFuzzyTitleStrategy_CrossVendorMatch(t *testing.T) {
	s := NewVendorFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Impact: 0.7, Title: strPtr("RHEL 9 must enable audit logging.")},
		{ID: "V-002", Impact: 0.5, Title: strPtr("RHEL 9 must configure SSH.")},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "AL-001", Impact: 0.7, Title: strPtr("Amazon Linux 2023 must enable audit logging.")},
		{ID: "AL-002", Impact: 0.5, Title: strPtr("Amazon Linux 2023 must configure SSH.")},
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 2)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestVendorFuzzyTitleStrategy_RejectUnrelated(t *testing.T) {
	s := NewVendorFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Impact: 0.7, Title: strPtr("RHEL 9 must enable audit logging.")},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "AL-001", Impact: 0.7, Title: strPtr("Amazon Linux 2023 must configure TLS certificates.")},
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestVendorFuzzyTitleStrategy_NoTitle(t *testing.T) {
	s := NewVendorFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "AL-001", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
}

func TestVendorFuzzyTitleStrategy_Empty(t *testing.T) {
	s := NewVendorFuzzyTitleStrategy(0)
	result := s.Match(nil, nil)
	assert.Len(t, result.Matched, 0)
}

func TestVendorFuzzyTitleStrategy_Relationship(t *testing.T) {
	s := NewVendorFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Impact: 0.7, Title: strPtr("RHEL 9 must enable audit logging.")},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "AL-001", Impact: 0.7, Title: strPtr("Amazon Linux 2023 must enable audit logging.")},
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "primary", result.Matched[0].Relationship)
}

func TestVendorFuzzyTitleStrategy_FeatureCorpus(t *testing.T) {
	s := NewVendorFuzzyTitleStrategy(0)
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Impact: 0.7, Title: strPtr("Ensure password complexity is set.")},
		{ID: "V-002", Impact: 0.5, Title: strPtr("Verify SSH is configured properly.")},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "R-001", Impact: 0.7, Title: strPtr("Ensure password complexity is set.")},
		{ID: "R-002", Impact: 0.5, Title: strPtr("Verify SSH is configured properly.")},
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 2)
}
