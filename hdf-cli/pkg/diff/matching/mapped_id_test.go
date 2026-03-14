package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMappedIdStrategy_Name(t *testing.T) {
	s := NewMappedIDStrategy(nil)
	assert.Equal(t, "mappedId", s.Name())
}

func TestMappedIdStrategy_MatchUsingMapping(t *testing.T) {
	mapping := map[string]string{"V-001-old": "V-001-new"}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001-old", Impact: 0.7, Title: strPtr("Test 1")},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001-new", Impact: 0.7, Title: strPtr("Test 1")},
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001-old", result.Matched[0].OldReq.ID)
	assert.Equal(t, "V-001-new", result.Matched[0].NewReq.ID)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestMappedIdStrategy_Confidence(t *testing.T) {
	mapping := map[string]string{"V-001-old": "V-001-new"}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001-old", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "V-001-new", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, 0.95, result.Matched[0].Confidence)
	assert.Equal(t, "mappedId", result.Matched[0].Strategy)
}

func TestMappedIdStrategy_UnmappedOldIDs(t *testing.T) {
	mapping := map[string]string{"V-001-old": "V-001-new"}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001-old", Impact: 0.7},
		{ID: "V-002-unmapped", Impact: 0.5},
	}
	newReqs := []hdf.EvaluatedRequirement{{ID: "V-001-new", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Equal(t, "V-002-unmapped", result.UnmatchedOld[0].ID)
}

func TestMappedIdStrategy_UnmatchedNewReqs(t *testing.T) {
	mapping := map[string]string{"V-001-old": "V-001-new"}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001-old", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001-new", Impact: 0.7},
		{ID: "V-003-extra", Impact: 0.3},
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedNew, 1)
	assert.Equal(t, "V-003-extra", result.UnmatchedNew[0].ID)
}

func TestMappedIdStrategy_EmptyMappingTable(t *testing.T) {
	s := NewMappedIDStrategy(map[string]string{})

	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	// No mappings: nothing is translated, so nothing matches
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestMappedIdStrategy_MultipleMappings(t *testing.T) {
	mapping := map[string]string{
		"V-001-old": "V-001-new",
		"V-002-old": "V-002-new",
		"V-003-old": "V-003-new",
	}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001-old", Impact: 0.7},
		{ID: "V-002-old", Impact: 0.5},
		{ID: "V-003-old", Impact: 0.3},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001-new", Impact: 0.7},
		{ID: "V-002-new", Impact: 0.5},
		{ID: "V-003-new", Impact: 0.3},
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 3)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestMappedIdStrategy_MappingToNonexistentNewID(t *testing.T) {
	mapping := map[string]string{"V-001-old": "V-001-nonexistent"}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001-old", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "V-001-actual", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestMappedIdStrategy_DuplicateNewIDs(t *testing.T) {
	mapping := map[string]string{"V-001-old": "V-001-new"}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001-old", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001-new", Impact: 0.7, Title: strPtr("New A")},
		{ID: "V-001-new", Impact: 0.5, Title: strPtr("New B")},
	}

	result := s.Match(oldReqs, newReqs)

	// Ambiguous: two new reqs share the mapped target ID -> neither can be matched
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 2)
}

func TestMappedIdStrategy_DuplicateOldIDs(t *testing.T) {
	mapping := map[string]string{"V-001-old": "V-001-new"}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001-old", Impact: 0.7, Title: strPtr("Old A")},
		{ID: "V-001-old", Impact: 0.5, Title: strPtr("Old B")},
	}
	newReqs := []hdf.EvaluatedRequirement{{ID: "V-001-new", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	// Ambiguous: two old reqs share the same ID -> neither can be matched
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 2)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestMappedIdStrategy_NilMapping(t *testing.T) {
	s := NewMappedIDStrategy(nil)

	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}
