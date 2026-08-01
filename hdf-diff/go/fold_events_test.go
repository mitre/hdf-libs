package diff

import (
	"encoding/json"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// feMapBatchReasons projects batch-vocabulary reasons onto the event
// vocabulary (the same mapping the kernel applies), as a set.
func feMapBatchReasons(reasons []ChangeReason) map[hdf.EventChangeReason]bool {
	out := map[hdf.EventChangeReason]bool{}
	for _, r := range reasons {
		if mapped := eventReasonFor(r); mapped != "" {
			out[mapped] = true
		}
	}
	return out
}

func feFoldReasonSet(reasons []ChangeReason) map[hdf.EventChangeReason]bool {
	out := map[hdf.EventChangeReason]bool{}
	for _, r := range reasons {
		out[hdf.EventChangeReason(r)] = true
	}
	return out
}

// feJSON canonicalizes any value for deep comparison.
func feJSON(t *testing.T, v interface{}) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}

// feBatchDiffs runs the batch engine in systemDrift mode and indexes the
// law-relevant entries (excluding unchanged — definitionally event-free —
// and the batch-only identity-resolution states).
func feBatchDiffs(t *testing.T, seedBytes, nextBytes []byte) map[string]RequirementDiff {
	t.Helper()
	var seedDoc, nextDoc hdf.HDFResults
	require.NoError(t, json.Unmarshal(seedBytes, &seedDoc))
	require.NoError(t, json.Unmarshal(nextBytes, &nextDoc))

	batch, err := DiffHdf(seedDoc, []hdf.HDFResults{nextDoc}, Options{ComparisonMode: ModeSystemDrift})
	require.NoError(t, err)

	out := map[string]RequirementDiff{}
	for _, d := range batch.RequirementDiffs {
		switch d.State {
		case StateUnchanged, StateMoved, StateSplit, StateMerged:
			continue
		}
		out[d.ID] = d
	}
	return out
}

func feFoldLawCheck(t *testing.T, seedName, nextName string) {
	t.Helper()
	seed := aeLoadFixture(t, seedName)
	next := aeLoadFixture(t, nextName)
	events := aeDeriveStream(t, seed, next)

	result, err := FoldChangeEventsIntoComparison(seed, events)
	require.NoError(t, err)
	assert.Empty(t, result.Warnings, "a complete derived stream must fold cleanly")

	want := feBatchDiffs(t, seed, next)
	got := map[string]RequirementDiff{}
	for _, d := range result.Comparison.RequirementDiffs {
		got[d.ID] = d
	}

	require.Equal(t, len(want), len(got), "fold and batch must agree on the changed-key set")
	for id, w := range want {
		g, ok := got[id]
		require.True(t, ok, "key %s missing from fold output", id)
		assert.Equal(t, w.State, g.State, "%s state", id)
		assert.Equal(t, w.OldEffectiveStatus, g.OldEffectiveStatus, "%s oldEffectiveStatus", id)
		assert.Equal(t, w.NewEffectiveStatus, g.NewEffectiveStatus, "%s newEffectiveStatus", id)
		assert.Equal(t, feJSON(t, w.OldImpact), feJSON(t, g.OldImpact), "%s oldImpact", id)
		assert.Equal(t, feJSON(t, w.NewImpact), feJSON(t, g.NewImpact), "%s newImpact", id)
		assert.Equal(t, w.Title, g.Title, "%s title", id)
		assert.Equal(t, w.Baseline, g.Baseline, "%s baseline", id)
		assert.Equal(t, feJSON(t, w.FieldChanges), feJSON(t, g.FieldChanges), "%s fieldChanges", id)
		assert.Equal(t, feJSON(t, w.Before), feJSON(t, g.Before), "%s before", id)
		assert.Equal(t, feJSON(t, w.After), feJSON(t, g.After), "%s after", id)
		assert.Equal(t, feMapBatchReasons(w.ChangeReasons), feFoldReasonSet(g.ChangeReasons),
			"%s changeReasons (through the event-vocabulary mapping)", id)
	}
}

func TestFoldChangeEvents_MatchesBatchDiff_ScanPair(t *testing.T) {
	feFoldLawCheck(t, "scan-before.json", "scan-after.json")
}

func TestFoldChangeEvents_MatchesBatchDiff_OverridePair(t *testing.T) {
	feFoldLawCheck(t, "scan-before.json", "scan-with-override.json")
}

func TestFoldChangeEvents_OutputShape(t *testing.T) {
	seed := aeLoadFixture(t, "scan-before.json")
	next := aeLoadFixture(t, "scan-after.json")
	events := aeDeriveStream(t, seed, next)

	result, err := FoldChangeEventsIntoComparison(seed, events)
	require.NoError(t, err)
	c := result.Comparison

	assert.Equal(t, ModeSystemDrift, c.ComparisonMode)
	assert.Equal(t, "fixture.hdf-system.json", c.SystemRef, "systemRef lifted from the events")
	assert.Equal(t, "1.0.0", c.FormatVersion)
	assert.Equal(t, "2024-02-01T00:00:00Z", c.Timestamp, "deterministic: max event occurrence, never wall clock")
	assert.NotEmpty(t, c.Sources)
	require.NotNil(t, c.Summary)
	assert.Len(t, c.RequirementDiffs, 5)

	raw, err := json.Marshal(c)
	require.NoError(t, err)
	validation := validators.ValidateComparison(raw)
	assert.True(t, validation.Valid, "folded comparison must be schema-valid: %v", validation.Errors)
}

func TestFoldChangeEvents_FoldContractProperties(t *testing.T) {
	seed := aeLoadFixture(t, "scan-before.json")
	next := aeLoadFixture(t, "scan-after.json")
	events := aeDeriveStream(t, seed, next)

	base, err := FoldChangeEventsIntoComparison(seed, events)
	require.NoError(t, err)

	t.Run("duplicate delivery is idempotent", func(t *testing.T) {
		doubled, err := FoldChangeEventsIntoComparison(seed, append(append([]*hdf.HDFRequirementChangeEvent{}, events...), events...))
		require.NoError(t, err)
		assert.Equal(t, feJSON(t, base.Comparison), feJSON(t, doubled.Comparison))
	})

	t.Run("delivery order is irrelevant", func(t *testing.T) {
		reversed := make([]*hdf.HDFRequirementChangeEvent, len(events))
		for i, ev := range events {
			reversed[len(events)-1-i] = ev
		}
		shuffled, err := FoldChangeEventsIntoComparison(seed, reversed)
		require.NoError(t, err)
		assert.Equal(t, feJSON(t, base.Comparison), feJSON(t, shuffled.Comparison))
	})
}

func TestFoldChangeEvents_Anomalies(t *testing.T) {
	seed, e1, e2 := aeTwoStepChain(t)

	t.Run("missing link warns but the winner still lifts", func(t *testing.T) {
		result, err := FoldChangeEventsIntoComparison(seed, []*hdf.HDFRequirementChangeEvent{e2})
		require.NoError(t, err)
		require.Len(t, result.Warnings, 1)
		assert.Equal(t, "chainGap", result.Warnings[0].Kind)
		require.Len(t, result.Comparison.RequirementDiffs, 1)
		assert.Equal(t, StateRegressed, result.Comparison.RequirementDiffs[0].State)
		_ = e1
	})

	t.Run("content-bearing chain for an unknown key coerces to new with a warning", func(t *testing.T) {
		passing := cePassingReq()
		passing.ID = "SV-424242"
		in := ceInputs()
		in.RequirementID = "SV-424242"
		in.Sequence = 3
		orphan := ChangeEventFromPrevious(&KeyState{
			EffectiveStatus: "failed", EffectiveImpact: 0.5,
			Checksum: hdf.Checksum{Algorithm: hdf.Sha256, Value: ecVectorFailedHalf},
		}, &passing, nil, in)
		require.NotNil(t, orphan)

		result, err := FoldChangeEventsIntoComparison(seed, []*hdf.HDFRequirementChangeEvent{orphan})
		require.NoError(t, err)
		require.Len(t, result.Warnings, 1)
		assert.Equal(t, "chainGap", result.Warnings[0].Kind)
		require.Len(t, result.Comparison.RequirementDiffs, 1)
		d := result.Comparison.RequirementDiffs[0]
		assert.Equal(t, StateNew, d.State,
			"the comparison vocabulary requires a null before only on new; the warning records the anomaly")
		assert.Nil(t, d.Before)

		raw, err := json.Marshal(result.Comparison)
		require.NoError(t, err)
		assert.True(t, validators.ValidateComparison(raw).Valid)
	})

	t.Run("absent for an unknown key warns and emits no entry", func(t *testing.T) {
		in := ceInputs()
		in.RequirementID = "SV-999999"
		in.Sequence = 4
		ghost := ChangeEventFromPrevious(&KeyState{
			EffectiveStatus: "failed", EffectiveImpact: 0.5,
			Checksum: hdf.Checksum{Algorithm: hdf.Sha256, Value: ecVectorFailedHalf},
		}, nil, nil, in)
		require.NotNil(t, ghost)

		result, err := FoldChangeEventsIntoComparison(seed, []*hdf.HDFRequirementChangeEvent{ghost})
		require.NoError(t, err)
		require.Len(t, result.Warnings, 1)
		assert.Equal(t, "absentUnknown", result.Warnings[0].Kind)
		assert.Empty(t, result.Comparison.RequirementDiffs)
	})

	t.Run("empty batch folds to an empty valid comparison", func(t *testing.T) {
		result, err := FoldChangeEventsIntoComparison(seed, nil)
		require.NoError(t, err)
		assert.Empty(t, result.Warnings)
		assert.Empty(t, result.Comparison.RequirementDiffs)
		raw, err := json.Marshal(result.Comparison)
		require.NoError(t, err)
		assert.True(t, validators.ValidateComparison(raw).Valid)
	})
}

// feTimestampLessSeed builds a seed from the shared fixture with the
// document timestamp removed and a deliberately-past waiver on SV-001:
// active at the 2024 event occurrence, expired by any later wall clock —
// so a wall-clock expiry anchor is observable as a wrong old status.
func feTimestampLessSeed(t *testing.T) ([]byte, hdf.EvaluatedRequirement) {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(aeLoadFixture(t, "scan-before.json"), &doc))
	delete(doc, "timestamp")

	baselines, _ := doc["baselines"].([]interface{})
	first, _ := baselines[0].(map[string]interface{})
	reqs, _ := first["requirements"].([]interface{})
	var seedReq hdf.EvaluatedRequirement
	for i, rRaw := range reqs {
		r, _ := rRaw.(map[string]interface{})
		if r["id"] != "SV-001" {
			continue
		}
		typed, ok := typedRequirement(r)
		require.True(t, ok)
		typed.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
			Type      string
			Status    hdf.ResultStatus
			Reason    string
			AppliedAt time.Time
			ExpiresAt time.Time
		}{
			Type:      "waiver",
			Status:    hdf.Passed,
			AppliedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		})}
		raw, err := json.Marshal(typed)
		require.NoError(t, err)
		var back map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &back))
		reqs[i] = back
		seedReq = typed
	}
	require.NotEmpty(t, seedReq.ID)
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out, seedReq
}

func TestFoldChangeEvents_TimestampLessSeedAnchorsToEventOccurrence(t *testing.T) {
	seed, seedReq := feTimestampLessSeed(t)
	refTs := "2024-02-01T00:00:00Z"

	cs := ComputeEffectiveChecksum(seedReq, refTs)
	require.NotNil(t, cs)
	prev := &KeyState{
		EffectiveStatus: ComputeEffectiveStatus(seedReq, refTs),
		EffectiveImpact: ComputeEffectiveImpact(seedReq, refTs),
		Checksum:        *cs,
	}
	require.Equal(t, "passed", prev.EffectiveStatus, "waiver must be active at the event occurrence")

	in := ceInputs()
	in.RequirementID = "SV-001"
	in.Timestamp = time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	in.ReferenceTimestamp = refTs
	in.PrevReferenceTimestamp = refTs

	t.Run("absent branch", func(t *testing.T) {
		ev := ChangeEventFromPrevious(prev, nil, &seedReq, in)
		require.NotNil(t, ev)
		result, err := FoldChangeEventsIntoComparison(seed, []*hdf.HDFRequirementChangeEvent{ev})
		require.NoError(t, err)
		assert.Empty(t, result.Warnings)
		require.Len(t, result.Comparison.RequirementDiffs, 1)
		assert.Equal(t, "passed", result.Comparison.RequirementDiffs[0].OldEffectiveStatus,
			"seed-side expiry must anchor to the event occurrence, never the wall clock")
	})

	t.Run("content branch", func(t *testing.T) {
		next := seedReq
		next.Impact = 0.6
		ev := ChangeEventFromPrevious(prev, &next, &seedReq, in)
		require.NotNil(t, ev)
		require.Equal(t, hdf.EventRequirementStateUpdated, ev.State)
		result, err := FoldChangeEventsIntoComparison(seed, []*hdf.HDFRequirementChangeEvent{ev})
		require.NoError(t, err)
		require.Len(t, result.Comparison.RequirementDiffs, 1)
		assert.Equal(t, "passed", result.Comparison.RequirementDiffs[0].OldEffectiveStatus,
			"seed-side expiry must anchor to the event occurrence, never the wall clock")
	})
}
