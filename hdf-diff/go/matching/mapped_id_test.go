package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
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

func TestMappedIdStrategy_DuplicateIDs(t *testing.T) {
	tests := []struct {
		name        string
		mapping     map[string]string
		oldReqs     []hdf.EvaluatedRequirement
		newReqs     []hdf.EvaluatedRequirement
		wantMatched int
		wantOldUnm  int
		wantNewUnm  int
	}{
		{
			name:    "duplicate new IDs - ambiguous target",
			mapping: map[string]string{"V-001-old": "V-001-new"},
			oldReqs: []hdf.EvaluatedRequirement{{ID: "V-001-old", Impact: 0.7}},
			newReqs: []hdf.EvaluatedRequirement{
				{ID: "V-001-new", Impact: 0.7, Title: strPtr("New A")},
				{ID: "V-001-new", Impact: 0.5, Title: strPtr("New B")},
			},
			wantMatched: 0,
			wantOldUnm:  1,
			wantNewUnm:  2,
		},
		{
			name:    "duplicate old IDs - ambiguous source",
			mapping: map[string]string{"V-001-old": "V-001-new"},
			oldReqs: []hdf.EvaluatedRequirement{
				{ID: "V-001-old", Impact: 0.7, Title: strPtr("Old A")},
				{ID: "V-001-old", Impact: 0.5, Title: strPtr("Old B")},
			},
			newReqs:     []hdf.EvaluatedRequirement{{ID: "V-001-new", Impact: 0.7}},
			wantMatched: 0,
			wantOldUnm:  2,
			wantNewUnm:  1,
		},
		{
			name:    "mapped target points to duplicate new ID",
			mapping: map[string]string{"V-001-old": "V-DUP"},
			oldReqs: []hdf.EvaluatedRequirement{{ID: "V-001-old", Impact: 0.7}},
			newReqs: []hdf.EvaluatedRequirement{
				{ID: "V-DUP", Impact: 0.7, Title: strPtr("A")},
				{ID: "V-DUP", Impact: 0.5, Title: strPtr("B")},
			},
			wantMatched: 0,
			wantOldUnm:  1,
			wantNewUnm:  2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMappedIDStrategy(tc.mapping)
			result := s.Match(tc.oldReqs, tc.newReqs)
			assert.Len(t, result.Matched, tc.wantMatched)
			assert.Len(t, result.UnmatchedOld, tc.wantOldUnm)
			assert.Len(t, result.UnmatchedNew, tc.wantNewUnm)
		})
	}
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

// ---------------------------------------------------------------------------
// Coverage: already-matched new ID — second old maps to same new
// ---------------------------------------------------------------------------

func TestMappedIdStrategy_AlreadyMatchedNewID(t *testing.T) {
	// Both V-001 and V-002 map to the same RHEL-001
	mapping := map[string]string{
		"V-001": "RHEL-001",
		"V-002": "RHEL-001",
	}
	s := NewMappedIDStrategy(mapping)

	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Impact: 0.7},
		{ID: "V-002", Impact: 0.5},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Impact: 0.7},
	}

	result := s.Match(oldReqs, newReqs)

	// First match wins; second old req is unmatched
	assert.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Equal(t, "V-002", result.UnmatchedOld[0].ID)
	assert.Len(t, result.UnmatchedNew, 0)
}

// ---------------------------------------------------------------------------
// Coverage: exact_id with triple duplicate old IDs
// ---------------------------------------------------------------------------

func TestExactIdStrategy_TripleDuplicateOldIDs(t *testing.T) {
	s := NewExactIDStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Impact: 0.7, Title: strPtr("A")},
		{ID: "SV-001", Impact: 0.5, Title: strPtr("B")},
		{ID: "SV-001", Impact: 0.3, Title: strPtr("C")},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Impact: 0.7, Title: strPtr("New")},
	}

	result := s.Match(oldReqs, newReqs)

	// All 3 old are duplicate IDs -> all unmatched
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 3)
	assert.Len(t, result.UnmatchedNew, 1)
}
