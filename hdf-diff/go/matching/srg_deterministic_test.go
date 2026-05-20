package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper to build a requirement with gtitle tag.
func reqWithGtitle(id, gtitle string) hdf.EvaluatedRequirement {
	return hdf.EvaluatedRequirement{
		ID:     id,
		Impact: 0.7,
		Tags:   map[string]any{"gtitle": gtitle},
	}
}

func TestSrgDeterministicStrategy_Name(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	assert.Equal(t, "srgDeterministic", s.Name())
}

func TestSrgDeterministicStrategy_Match1to1(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithGtitle("V-001", "SRG-OS-000185-GPOS-00079")}
	newReqs := []hdf.EvaluatedRequirement{reqWithGtitle("RHEL-001", "SRG-OS-000185-GPOS-00079")}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
	assert.Equal(t, "RHEL-001", result.Matched[0].NewReq.ID)
	assert.Equal(t, "srgDeterministic", result.Matched[0].Strategy)
	assert.Equal(t, 1.0, result.Matched[0].Confidence)
	assert.Equal(t, "primary", result.Matched[0].Relationship)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestSrgDeterministicStrategy_NNewOneOld(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithGtitle("V-001", "SRG-OS-000185-GPOS-00079")}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithGtitle("RHEL-001", "SRG-OS-000185-GPOS-00079"),
		reqWithGtitle("RHEL-002", "SRG-OS-000185-GPOS-00079"),
		reqWithGtitle("RHEL-003", "SRG-OS-000185-GPOS-00079"),
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 3)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)

	// First new gets primary
	assert.Equal(t, "RHEL-001", result.Matched[0].NewReq.ID)
	assert.Equal(t, "primary", result.Matched[0].Relationship)

	// Rest get related
	assert.Equal(t, "RHEL-002", result.Matched[1].NewReq.ID)
	assert.Equal(t, "related", result.Matched[1].Relationship)
	assert.Equal(t, "RHEL-003", result.Matched[2].NewReq.ID)
	assert.Equal(t, "related", result.Matched[2].Relationship)

	// All reference same old req
	for _, m := range result.Matched {
		assert.Equal(t, "V-001", m.OldReq.ID)
		assert.Equal(t, 1.0, m.Confidence)
	}
}

func TestSrgDeterministicStrategy_OneNewNOld(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithGtitle("V-001", "SRG-OS-000185-GPOS-00079"),
		reqWithGtitle("V-002", "SRG-OS-000185-GPOS-00079"),
	}
	newReqs := []hdf.EvaluatedRequirement{reqWithGtitle("RHEL-001", "SRG-OS-000185-GPOS-00079")}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 2)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)

	// First old gets primary
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
	assert.Equal(t, "primary", result.Matched[0].Relationship)

	// Second old gets related
	assert.Equal(t, "V-002", result.Matched[1].OldReq.ID)
	assert.Equal(t, "related", result.Matched[1].Relationship)

	// Both reference same new req
	for _, m := range result.Matched {
		assert.Equal(t, "RHEL-001", m.NewReq.ID)
	}
}

func TestSrgDeterministicStrategy_NMAmbiguous(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithGtitle("V-001", "SRG-OS-000185-GPOS-00079"),
		reqWithGtitle("V-002", "SRG-OS-000185-GPOS-00079"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithGtitle("RHEL-001", "SRG-OS-000185-GPOS-00079"),
		reqWithGtitle("RHEL-002", "SRG-OS-000185-GPOS-00079"),
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 2)
	assert.Len(t, result.UnmatchedNew, 2)
}

func TestSrgDeterministicStrategy_NoGtitle(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7, Tags: map[string]any{"nist": "AC-1"}}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "RHEL-001", Impact: 0.7, Tags: map[string]any{"nist": "AC-1"}}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestSrgDeterministicStrategy_NoTags(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "RHEL-001", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestSrgDeterministicStrategy_MixedMatchAndNoMatch(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithGtitle("V-001", "SRG-OS-000001"),
		reqWithGtitle("V-002", "SRG-OS-000002"),
		{ID: "V-003", Impact: 0.3},
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithGtitle("RHEL-001", "SRG-OS-000001"),
		reqWithGtitle("RHEL-002", "SRG-OS-000999"),
		{ID: "RHEL-003", Impact: 0.3},
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
	assert.Equal(t, "RHEL-001", result.Matched[0].NewReq.ID)
	assert.Equal(t, "primary", result.Matched[0].Relationship)

	assert.Len(t, result.UnmatchedOld, 2)
	assert.Len(t, result.UnmatchedNew, 2)
}

func TestSrgDeterministicStrategy_MultipleDistinctGtitles(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithGtitle("V-001", "SRG-OS-000001"),
		reqWithGtitle("V-002", "SRG-OS-000002"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithGtitle("RHEL-001", "SRG-OS-000001"),
		reqWithGtitle("RHEL-002", "SRG-OS-000002"),
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 2)
	// Map iteration order not guaranteed — check by content not position
	matchedPairs := make(map[string]string)
	for _, m := range result.Matched {
		matchedPairs[m.OldReq.ID] = m.NewReq.ID
	}
	assert.Equal(t, "RHEL-001", matchedPairs["V-001"])
	assert.Equal(t, "RHEL-002", matchedPairs["V-002"])
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestSrgDeterministicStrategy_EmptyInputs(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	result := s.Match(nil, nil)
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestSrgDeterministicStrategy_EmptyGtitle(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Impact: 0.7, Tags: map[string]any{"gtitle": ""}},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Impact: 0.7, Tags: map[string]any{"gtitle": ""}},
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestSrgDeterministicStrategy_GtitleNotString(t *testing.T) {
	s := NewSRGDeterministicStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Impact: 0.7, Tags: map[string]any{"gtitle": 42}},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Impact: 0.7, Tags: map[string]any{"gtitle": 42}},
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}
