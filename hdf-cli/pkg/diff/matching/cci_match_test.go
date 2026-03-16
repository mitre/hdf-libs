package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper to build a requirement with ID and CCI tags.
func reqWithCCI(id string, ccis []string) hdf.EvaluatedRequirement {
	tags := map[string]any{}
	cciSlice := make([]any, len(ccis))
	for i, c := range ccis {
		cciSlice[i] = c
	}
	tags["cci"] = cciSlice
	return hdf.EvaluatedRequirement{
		ID:     id,
		Impact: 0.7,
		Tags:   tags,
	}
}

func TestCciMatchStrategy_Name(t *testing.T) {
	s := NewCCIMatchStrategy()
	assert.Equal(t, "cciMatch", s.Name())
}

func TestCciMatchStrategy_MatchSharedCCI(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithCCI("V-001", []string{"CCI-000366"})}
	newReqs := []hdf.EvaluatedRequirement{reqWithCCI("RHEL-001", []string{"CCI-000366"})}

	result := s.Match(oldReqs, newReqs)

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
	assert.Equal(t, "RHEL-001", result.Matched[0].NewReq.ID)
	assert.Equal(t, 0.8, result.Matched[0].Confidence)
	assert.Equal(t, "cciMatch", result.Matched[0].Strategy)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestCciMatchStrategy_AmbiguousMultipleOld(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("V-001", []string{"CCI-000366"}),
		reqWithCCI("V-002", []string{"CCI-000366"}),
	}
	newReqs := []hdf.EvaluatedRequirement{reqWithCCI("RHEL-001", []string{"CCI-000366"})}

	result := s.Match(oldReqs, newReqs)

	// Ambiguous: two old reqs share the same CCI
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 2)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestCciMatchStrategy_AmbiguousMultipleNew(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithCCI("V-001", []string{"CCI-000366"})}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("RHEL-001", []string{"CCI-000366"}),
		reqWithCCI("RHEL-002", []string{"CCI-000366"}),
	}

	result := s.Match(oldReqs, newReqs)

	// Ambiguous: two new reqs share the same CCI
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 2)
}

func TestCciMatchStrategy_MultipleUnambiguousCCIs(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("V-001", []string{"CCI-000366"}),
		reqWithCCI("V-002", []string{"CCI-000777"}),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("RHEL-001", []string{"CCI-000366"}),
		reqWithCCI("RHEL-002", []string{"CCI-000777"}),
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 2)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestCciMatchStrategy_MultipleCCIsOnRequirement(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("V-001", []string{"CCI-000366", "CCI-000777"}),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("RHEL-001", []string{"CCI-000366", "CCI-000777"}),
	}

	result := s.Match(oldReqs, newReqs)

	// Should match on the first unambiguous CCI found
	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestCciMatchStrategy_NoTags(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "RHEL-001", Impact: 0.7}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestCciMatchStrategy_EmptyCCIArray(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithCCI("V-001", []string{})}
	newReqs := []hdf.EvaluatedRequirement{reqWithCCI("RHEL-001", []string{})}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestCciMatchStrategy_TagsButNoCCI(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Impact: 0.7, Tags: map[string]any{"nist": []any{"AC-1"}}},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Impact: 0.7, Tags: map[string]any{"nist": []any{"AC-1"}}},
	}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestCciMatchStrategy_ConservativeMultiCCIAmbiguity(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("V-A", []string{"CCI-001", "CCI-002"}),
		reqWithCCI("V-B", []string{"CCI-002"}),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("RHEL-X", []string{"CCI-001"}),
		reqWithCCI("RHEL-Y", []string{"CCI-002"}),
	}

	result := s.Match(oldReqs, newReqs)

	// CCI-001: unambiguous (1 old V-A, 1 new RHEL-X) -> matched
	// CCI-002: ambiguous (2 old V-A+V-B, 1 new RHEL-Y) -> skipped
	require.Len(t, result.Matched, 1)
	assert.Equal(t, "V-A", result.Matched[0].OldReq.ID)
	assert.Equal(t, "RHEL-X", result.Matched[0].NewReq.ID)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Equal(t, "V-B", result.UnmatchedOld[0].ID)
	assert.Len(t, result.UnmatchedNew, 1)
	assert.Equal(t, "RHEL-Y", result.UnmatchedNew[0].ID)
}

func TestCciMatchStrategy_CCIOnlyInOld(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{reqWithCCI("V-001", []string{"CCI-999"})}
	newReqs := []hdf.EvaluatedRequirement{reqWithCCI("V-002", []string{"CCI-888"})}

	result := s.Match(oldReqs, newReqs)

	// No shared CCIs
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestCciMatchStrategy_MixMatchableAndAmbiguous(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("V-001", []string{"CCI-000366"}),
		reqWithCCI("V-002", []string{"CCI-000777"}),
		reqWithCCI("V-003", []string{"CCI-000777"}),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("RHEL-001", []string{"CCI-000366"}),
		reqWithCCI("RHEL-002", []string{"CCI-000777"}),
	}

	result := s.Match(oldReqs, newReqs)

	// CCI-000366: unambiguous (1 old, 1 new) -> matched
	// CCI-000777: ambiguous (2 old, 1 new) -> unmatched
	assert.Len(t, result.Matched, 1)
	assert.Equal(t, "V-001", result.Matched[0].OldReq.ID)
	assert.Len(t, result.UnmatchedOld, 2)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestCciMatchStrategy_NilTagsMap(t *testing.T) {
	s := NewCCIMatchStrategy()
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7, Tags: nil}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "RHEL-001", Impact: 0.7, Tags: nil}}

	result := s.Match(oldReqs, newReqs)

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

// ---------------------------------------------------------------------------
// Coverage: extractCCIs — CCI value is not []any (e.g., a string)
// ---------------------------------------------------------------------------

func TestExtractCCIs_CCINotSlice(t *testing.T) {
	req := hdf.EvaluatedRequirement{
		ID:     "V-001",
		Impact: 0.7,
		Tags:   map[string]any{"cci": "CCI-000366"},
	}
	result := extractCCIs(req)
	assert.Nil(t, result, "extractCCIs should return nil when cci is not []any")
}

func TestExtractCCIs_CCIMixedTypes(t *testing.T) {
	req := hdf.EvaluatedRequirement{
		ID:     "V-001",
		Impact: 0.7,
		Tags: map[string]any{
			"cci": []any{"CCI-000366", 42, "CCI-000777"},
		},
	}
	result := extractCCIs(req)
	// Only string elements should be extracted
	assert.Len(t, result, 2)
	assert.Equal(t, "CCI-000366", result[0])
	assert.Equal(t, "CCI-000777", result[1])
}

func TestExtractCCIs_NilTags(t *testing.T) {
	req := hdf.EvaluatedRequirement{ID: "V-001", Impact: 0.7, Tags: nil}
	result := extractCCIs(req)
	assert.Nil(t, result)
}

func TestExtractCCIs_NoCCIKey(t *testing.T) {
	req := hdf.EvaluatedRequirement{
		ID:     "V-001",
		Impact: 0.7,
		Tags:   map[string]any{"nist": []any{"AC-1"}},
	}
	result := extractCCIs(req)
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// Coverage: CCI Match — already-matched old/new indices get skipped
// ---------------------------------------------------------------------------

func TestCciMatchStrategy_DoubleMatchPrevention(t *testing.T) {
	s := NewCCIMatchStrategy()
	// Two requirements share two CCIs — should only match once
	oldReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("V-001", []string{"CCI-001", "CCI-002"}),
	}
	newReqs := []hdf.EvaluatedRequirement{
		reqWithCCI("RHEL-001", []string{"CCI-001", "CCI-002"}),
	}

	result := s.Match(oldReqs, newReqs)

	// Should produce exactly 1 match, not 2
	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}
