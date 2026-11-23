package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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

	// Superseded: a second occurrence no longer makes the id unusable. The old
	// entry's content matches neither new one, so position pairs it with the first and the
	// second is reported new.
	require.Len(t, result.Matched, 1)
	assert.Equal(t, "Old", *result.Matched[0].OldReq.Title)
	assert.Equal(t, "New A", *result.Matched[0].NewReq.Title)
	assert.Empty(t, result.UnmatchedOld)
	require.Len(t, result.UnmatchedNew, 1)
	assert.Equal(t, "New B", *result.UnmatchedNew[0].Title)
}

func TestExactIdStrategy_DuplicateOldIDs(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "Old A"),
		reqWithIDAndTitle("SV-001", "Old B"),
	}
	newReqs := []hdf.EvaluatedRequirement{reqWithIDAndTitle("SV-001", "New")}

	result := s.Match(oldReqs, newReqs)

	// Superseded: one occurrence pairs, the surplus is reported absent, rather
	// than every occurrence being abandoned.
	require.Len(t, result.Matched, 1)
	assert.Equal(t, "Old A", *result.Matched[0].OldReq.Title)
	require.Len(t, result.UnmatchedOld, 1)
	assert.Equal(t, "Old B", *result.UnmatchedOld[0].Title)
	assert.Empty(t, result.UnmatchedNew)
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

// A duplicated id is N occurrences of one requirement, paired by content key with
// document position as the tie-break. It was once called ambiguous, so a
// self-comparison reported every duplicated entry absent AND new.

func TestExactIdStrategy_IdenticalDuplicateIDsOnBothSides(t *testing.T) {
	s := NewExactIDStrategy()
	reqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "A"),
		reqWithIDAndTitle("SV-001", "B"),
	}

	result := s.Match(reqs, reqs)

	require.Len(t, result.Matched, 2)
	assert.Empty(t, result.UnmatchedOld)
	assert.Empty(t, result.UnmatchedNew)
	// The pairing, not just the counts: crossing the pair passes a count assertion.
	for _, pair := range result.Matched {
		assert.Equal(t, *pair.OldReq.Title, *pair.NewReq.Title)
	}
}

func TestExactIdStrategy_DuplicateIDsPairByContentWhenReordered(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "A"),
		reqWithIDAndTitle("SV-001", "B"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "B"),
		reqWithIDAndTitle("SV-001", "A"),
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 2)
	assert.Empty(t, result.UnmatchedOld)
	assert.Empty(t, result.UnmatchedNew)
	// Content decides, so a producer that reorders its output reports no change.
	for _, pair := range result.Matched {
		assert.Equal(t, *pair.OldReq.Title, *pair.NewReq.Title)
	}
}

func TestExactIdStrategy_DuplicateIDsSurplusOnNewSide(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithIDAndTitle("SV-001", "A")}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "A"),
		reqWithIDAndTitle("SV-001", "B"),
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "A", *result.Matched[0].OldReq.Title)
	assert.Equal(t, "A", *result.Matched[0].NewReq.Title)
	assert.Empty(t, result.UnmatchedOld)
	require.Len(t, result.UnmatchedNew, 1)
	assert.Equal(t, "B", *result.UnmatchedNew[0].Title)
}

func TestExactIdStrategy_DuplicateIDsSurplusOnOldSide(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithIDAndTitle("SV-001", "A"),
		reqWithIDAndTitle("SV-001", "B"),
	}
	newReqs := []hdf.EvaluatedRequirement{reqWithIDAndTitle("SV-001", "A")}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "A", *result.Matched[0].OldReq.Title)
	require.Len(t, result.UnmatchedOld, 1)
	assert.Equal(t, "B", *result.UnmatchedOld[0].Title)
	assert.Empty(t, result.UnmatchedNew)
}

func TestExactIdStrategy_IndistinguishableDuplicatesPairByPosition(t *testing.T) {
	s := NewExactIDStrategy()
	// Byte-identical occurrences: no content key can separate them, so position decides —
	// which is right here, because the entries are interchangeable.
	reqs := []hdf.EvaluatedRequirement{reqWithID("SV-001"), reqWithID("SV-001")}

	result := s.Match(reqs, reqs)

	assert.Len(t, result.Matched, 2)
	assert.Empty(t, result.UnmatchedOld)
	assert.Empty(t, result.UnmatchedNew)
}
