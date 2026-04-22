package matching

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchRequirements_DefaultExactId(t *testing.T) {
	oldReqs := []hdf.EvaluatedRequirement{{ID: "SV-001", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "SV-001", Impact: 0.7}}

	result := MatchRequirements(oldReqs, newReqs, Options{})

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "exactId", result.Matched[0].Strategy)
	assert.Equal(t, 1.0, result.Matched[0].Confidence)
}

func TestMatchRequirements_SpecifiedStrategy(t *testing.T) {
	mapping := map[string]string{"V-001-old": "V-001-new"}
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001-old", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "V-001-new", Impact: 0.7}}

	result := MatchRequirements(oldReqs, newReqs, Options{
		Strategy:     "mappedId",
		MappingTable: mapping,
	})

	require.Len(t, result.Matched, 1)
	assert.Equal(t, "mappedId", result.Matched[0].Strategy)
	assert.Equal(t, 0.95, result.Matched[0].Confidence)
}

func TestMatchRequirements_MappedIdNoMappingTable(t *testing.T) {
	oldReqs := []hdf.EvaluatedRequirement{{ID: "V-001", Impact: 0.7}}
	newReqs := []hdf.EvaluatedRequirement{{ID: "V-002", Impact: 0.7}}

	result := MatchRequirements(oldReqs, newReqs, Options{Strategy: "mappedId"})

	// Empty mapping = nothing matches
	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestMatchRequirements_FallbackStrategies(t *testing.T) {
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
		{ID: "V-002-old", Title: strPtr("Configure NTP time synchronization"), Impact: 0.5},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
		{ID: "RHEL-002", Title: strPtr("Configure NTP time synchronization"), Impact: 0.5},
	}

	result := MatchRequirements(oldReqs, newReqs, Options{
		Strategy:           "exactId",
		FallbackStrategies: []string{"fuzzyTitle"},
	})

	// SV-001 matched by exactId, V-002-old -> RHEL-002 matched by fuzzyTitle
	require.Len(t, result.Matched, 2)

	strategies := make(map[string]bool)
	for _, m := range result.Matched {
		strategies[m.Strategy] = true
	}
	assert.True(t, strategies["exactId"])
	assert.True(t, strategies["fuzzyTitle"])
}

func TestMatchRequirements_ChainMultipleFallbacks(t *testing.T) {
	mapping := map[string]string{"V-002-old": "V-002-new"}
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Title: strPtr("SSH check"), Impact: 0.7},
		{ID: "V-002-old", Title: strPtr("NTP check"), Impact: 0.5},
		{ID: "V-003", Title: strPtr("Ensure audit logging is enabled"), Impact: 0.3,
			Tags: map[string]any{"cci": []any{"CCI-000366"}}},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Title: strPtr("SSH check"), Impact: 0.7},
		{ID: "V-002-new", Title: strPtr("NTP check"), Impact: 0.5},
		{ID: "RHEL-003", Title: strPtr("Audit logging configuration"), Impact: 0.3,
			Tags: map[string]any{"cci": []any{"CCI-000366"}}},
	}

	result := MatchRequirements(oldReqs, newReqs, Options{
		Strategy:           "exactId",
		FallbackStrategies: []string{"mappedId", "cciMatch"},
		MappingTable:       mapping,
	})

	assert.Len(t, result.Matched, 3)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)

	strategies := make(map[string]bool)
	for _, m := range result.Matched {
		strategies[m.Strategy] = true
	}
	assert.True(t, strategies["exactId"])
	assert.True(t, strategies["mappedId"])
	assert.True(t, strategies["cciMatch"])
}

func TestMatchRequirements_RespectMinConfidence(t *testing.T) {
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr("Ensure SSH root login is disabled"), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr("SSH root login must be disabled"), Impact: 0.7},
	}

	result := MatchRequirements(oldReqs, newReqs, Options{
		Strategy:      "fuzzyTitle",
		MinConfidence: 0.95,
	})

	// Similarity is around 0.7-0.8, below 0.95
	assert.Len(t, result.Matched, 0)
}

func TestMatchRequirements_UnknownStrategy(t *testing.T) {
	_, err := MatchRequirementsWithError(nil, nil, Options{Strategy: "nonexistent"})
	assert.Error(t, err)
}

func TestMatchRequirements_UnknownFallbackStrategy(t *testing.T) {
	_, err := MatchRequirementsWithError(nil, nil, Options{
		Strategy:           "exactId",
		FallbackStrategies: []string{"nonexistent"},
	})
	assert.Error(t, err)
}

func TestMatchRequirements_PassThroughAfterExhausted(t *testing.T) {
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "V-001", Title: strPtr("Totally unique old requirement"), Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "RHEL-001", Title: strPtr("Completely different new check"), Impact: 0.5},
	}

	result := MatchRequirements(oldReqs, newReqs, Options{
		Strategy:           "exactId",
		FallbackStrategies: []string{"fuzzyTitle"},
	})

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestMatchRequirements_EmptyInputs(t *testing.T) {
	result := MatchRequirements(nil, nil, Options{})

	assert.Len(t, result.Matched, 0)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

func TestMatchRequirements_AccumulateFromAllLayers(t *testing.T) {
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Impact: 0.7},
		{ID: "SV-002", Impact: 0.5,
			Tags: map[string]any{"cci": []any{"CCI-000366"}}},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Impact: 0.7},
		{ID: "RHEL-002", Impact: 0.5,
			Tags: map[string]any{"cci": []any{"CCI-000366"}}},
	}

	result := MatchRequirements(oldReqs, newReqs, Options{
		Strategy:           "exactId",
		FallbackStrategies: []string{"cciMatch"},
	})

	assert.Len(t, result.Matched, 2)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 0)
}

// ---------------------------------------------------------------------------
// Coverage: MatchRequirements — early break when one side exhausted
// ---------------------------------------------------------------------------

func TestMatchRequirements_EarlyBreakAllOldMatched(t *testing.T) {
	// All old reqs match on primary strategy; fallback should be skipped
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Impact: 0.7},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Impact: 0.7},
		{ID: "SV-002", Impact: 0.5},
	}

	result := MatchRequirements(oldReqs, newReqs, Options{
		Strategy:           "exactId",
		FallbackStrategies: []string{"fuzzyTitle"},
	})

	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedOld, 0)
	assert.Len(t, result.UnmatchedNew, 1)
}

func TestMatchRequirements_EarlyBreakAllNewMatched(t *testing.T) {
	// All new reqs match on primary strategy; fallback skipped for remaining old
	oldReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Impact: 0.7},
		{ID: "SV-002", Impact: 0.5},
	}
	newReqs := []hdf.EvaluatedRequirement{
		{ID: "SV-001", Impact: 0.7},
	}

	result := MatchRequirements(oldReqs, newReqs, Options{
		Strategy:           "exactId",
		FallbackStrategies: []string{"fuzzyTitle"},
	})

	assert.Len(t, result.Matched, 1)
	assert.Len(t, result.UnmatchedOld, 1)
	assert.Len(t, result.UnmatchedNew, 0)
}

// ---------------------------------------------------------------------------
// Coverage: MatchRequirements — panic on unknown strategy
// ---------------------------------------------------------------------------

func TestMatchRequirements_PanicsOnUnknownStrategy(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic on unknown strategy, but did not panic")
		}
	}()
	MatchRequirements(nil, nil, Options{Strategy: "nonexistent"})
}
