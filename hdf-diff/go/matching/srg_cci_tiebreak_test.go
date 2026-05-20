package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reqWithSRG builds a requirement with gtitle, CCI tags, and title.
func reqWithSRG(id, gtitle string, ccis []string, title string) hdf.EvaluatedRequirement {
	tags := map[string]any{"gtitle": gtitle}
	if len(ccis) > 0 {
		cciSlice := make([]any, len(ccis))
		for i, c := range ccis {
			cciSlice[i] = c
		}
		tags["cci"] = cciSlice
	}
	var titlePtr *string
	if title != "" {
		titlePtr = &title
	}
	return hdf.EvaluatedRequirement{
		ID:     id,
		Impact: 0.7,
		Tags:   tags,
		Title:  titlePtr,
	}
}

func TestSrgCciTiebreakStrategy_Name(t *testing.T) {
	s := NewSRGCCITiebreakStrategy()
	assert.Equal(t, "srgCciTiebreak", s.Name())
}

func TestSrgCciTiebreakStrategy_MultipleOldOneSRG(t *testing.T) {
	s := NewSRGCCITiebreakStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("V-001", "SRG-OS-000001", []string{"CCI-000366", "CCI-000777"}, "Enable audit logging"),
		reqWithSRG("V-002", "SRG-OS-000001", []string{"CCI-000888"}, "Enable remote logging"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("RHEL-001", "SRG-OS-000001", []string{"CCI-000366", "CCI-000777"}, "Enable audit logging"),
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
	assert.Equal(t, "RHEL-001", result.Matched[0].NewReq.ID)
	assert.Equal(t, "srgCciTiebreak", result.Matched[0].Strategy)
	assert.Equal(t, "primary", result.Matched[0].Relationship)
	assert.Greater(t, result.Matched[0].Confidence, 0.0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Equal(t, "V-002", result.UnmatchedOld[0].ID)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestSrgCciTiebreakStrategy_MultipleNewOneSRG(t *testing.T) {
	s := NewSRGCCITiebreakStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("V-001", "SRG-OS-000001", []string{"CCI-000366"}, "Enable audit logging"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("RHEL-001", "SRG-OS-000001", []string{"CCI-000366"}, "Enable audit logging"),
		reqWithSRG("RHEL-002", "SRG-OS-000001", []string{"CCI-000888"}, "Enable remote logging"),
	}

	result := s.Match(oldReqs, newReqs)

	// 2 new + 1 old → both get matched (greedy), best first is primary
	require.Len(t, result.Matched, 2)
	// First matched should be primary with the best CCI score
	assert.Equal(t, "primary", result.Matched[0].Relationship)
	assert.Equal(t, "related", result.Matched[1].Relationship)
	assert.Len(t, result.UnmatchedNew, 0)
	assert.Len(t, result.UnmatchedOld, 0)
}

func TestSrgCciTiebreakStrategy_PrefersUnclaimed(t *testing.T) {
	s := NewSRGCCITiebreakStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("V-001", "SRG-OS-000001", []string{"CCI-000366"}, "Enable audit logging"),
		reqWithSRG("V-002", "SRG-OS-000001", []string{"CCI-000366"}, "Enable audit logging"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("RHEL-001", "SRG-OS-000001", []string{"CCI-000366"}, "Enable audit logging"),
		reqWithSRG("RHEL-002", "SRG-OS-000001", []string{"CCI-000366"}, "Enable audit logging"),
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 2)
	matchedOldIDs := []string{result.Matched[0].OldReq.ID, result.Matched[1].OldReq.ID}
	assert.Contains(t, matchedOldIDs, "V-001")
	assert.Contains(t, matchedOldIDs, "V-002")
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestSrgCciTiebreakStrategy_NoCCITitleOnly(t *testing.T) {
	s := NewSRGCCITiebreakStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("V-001", "SRG-OS-000001", nil, "Enable audit logging"),
		reqWithSRG("V-002", "SRG-OS-000001", nil, "Enable remote logging"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("RHEL-001", "SRG-OS-000001", nil, "Enable audit logging"),
	}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
}

func TestSrgCciTiebreakStrategy_SkipsNoGtitle(t *testing.T) {
	s := NewSRGCCITiebreakStrategy()
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7, Tags: map[string]any{"nist": "AC-1"}}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "RHEL-001", Impact: 0.7, Tags: map[string]any{"nist": "AC-1"}}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestSrgCciTiebreakStrategy_Skips1to1(t *testing.T) {
	s := NewSRGCCITiebreakStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("V-001", "SRG-OS-000001", []string{"CCI-000366"}, "Enable audit"),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithSRG("RHEL-001", "SRG-OS-000001", []string{"CCI-000366"}, "Enable audit"),
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestSrgCciTiebreakStrategy_Empty(t *testing.T) {
	s := NewSRGCCITiebreakStrategy()
	result := s.Match(nil, nil)
	assert.Len(t, result.Matched, 0)
}
