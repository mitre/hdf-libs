package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper to build a minimal EvaluatedRequirement with an ID.
func reqWithID(id string) hdf.EvaluatedRequirement {
	return hdf.EvaluatedRequirement{
		ID:     id,
		Impact: 0.7,
	}
}

// helper to build a requirement with ID and title.
func reqWithIDAndTitle(id, title string) hdf.EvaluatedRequirement {
	return hdf.EvaluatedRequirement{
		ID:     id,
		Impact: 0.7,
		Title:  strPtr(title),
	}
}

// helper to create a string pointer.
func strPtr(s string) *string {
	return &s
}

func TestExactIdStrategy_Name(t *testing.T) {
	s := NewExactIDStrategy()
	assert.Equal(t, "exactId", s.Name())
}

func TestExactIdStrategy_MatchSameIDs(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "Test 1"),
		reqWithIDAndTitle("SV-002", "Test 2"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "Test 1 updated"),
		reqWithIDAndTitle("SV-002", "Test 2"),
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 2)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestExactIdStrategy_Confidence(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithID("SV-001")}
	newReqs := []hdf.EvaluatedRequirement{reqWithID("SV-001")}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, 1.0, result.Matched[0].Confidence)
	assert.Equal(t, "exactId", result.Matched[0].Strategy)
}

func TestExactIdStrategy_OldOnlyUnmatched(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithID("SV-001"),
		reqWithID("SV-002"),
	}
	newReqs := []hdf.EvaluatedRequirement{reqWithID("SV-001")}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Equal(t, "SV-002", result.UnmatchedOld[0].ID)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestExactIdStrategy_NewOnlyUnmatched(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithID("SV-001")}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithID("SV-001"),
		reqWithID("SV-003"),
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 1)
	assert.Equal(t, "SV-003", result.UnmatchedNew[0].ID)
}

func TestExactIdStrategy_EmptyOld(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{}
	newReqs := []hdf.EvaluatedRequirement{reqWithID("SV-001")}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestExactIdStrategy_EmptyNew(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithID("SV-001")}
	newReqs := []hdf.EvaluatedRequirement{}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestExactIdStrategy_BothEmpty(t *testing.T) {
	s := NewExactIDStrategy()
	result := s.Match(nil, nil)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestExactIdStrategy_EmptyIDsUnmatched(t *testing.T) {
	s := NewExactIDStrategy()
	// Requirements with empty string IDs should be treated as having an ID
	// (empty string is still a valid string), but they will match each other.
	// In Go, the ID field is always a string (not *string), so we test with empty IDs.
	oldReqs := []hdf.EvaluatedRequirement{{ID: "", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	// Empty string IDs match each other since they are equal strings
	assert.Len(t, result.Matched, 1)
}

func TestExactIdStrategy_CorrectPairing(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithIDAndTitle("SV-001", "Old Title")}
	newReqs := []hdf.EvaluatedRequirement{reqWithIDAndTitle("SV-001", "New Title")}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "Old Title", *result.Matched[0].OldReq.Title)
	assert.Equal(t, "New Title", *result.Matched[0].NewReq.Title)
}

func TestExactIdStrategy_DuplicateNewIDs(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithIDAndTitle("SV-001", "Old")}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "New A"),
		reqWithIDAndTitle("SV-001", "New B"),
	}

	result := s.Match(oldReqs, newReqs)

	// Ambiguous: two new reqs share the same ID -> neither can be matched
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 2)
}

func TestExactIdStrategy_DuplicateOldIDs(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "Old A"),
		reqWithIDAndTitle("SV-001", "Old B"),
	}
	newReqs := []hdf.EvaluatedRequirement{reqWithIDAndTitle("SV-001", "New")}

	result := s.Match(oldReqs, newReqs)

	// Ambiguous: two old reqs share the same ID -> neither can be matched
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 2)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestExactIdStrategy_MixedMatchAndUnmatched(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithID("SV-001"),
		reqWithID("SV-002"),
		reqWithID("SV-003"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithID("SV-001"),
		reqWithID("SV-003"),
		reqWithID("SV-004"),
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 2)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Equal(t, "SV-002", result.UnmatchedOld[0].ID)
	assert.Len(t, result.UnmatchedNew, 1)
	assert.Equal(t, "SV-004", result.UnmatchedNew[0].ID)
}
