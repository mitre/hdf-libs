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

func ceInputs() EventInputs {
	return EventInputs{
		EventID:            "0190f6f2-1c4e-7c3a-9f2a-3b1d5e7a9c01",
		Source:             "inspec://web01/rhel9-stig",
		Sequence:           412,
		SystemRef:          "apptier.hdf-system.json",
		ComponentID:        "6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60",
		RequirementID:      "SV-100001",
		Timestamp:          time.Date(2026, 7, 22, 14, 3, 11, 0, time.UTC),
		ReferenceTimestamp: "2026-07-22T14:03:11Z",
	}
}

func cePrevFailing() *KeyState {
	return &KeyState{
		EffectiveStatus: "failed",
		EffectiveImpact: 0.5,
		Checksum:        hdf.Checksum{Algorithm: hdf.Sha256, Value: ecVectorFailedHalf},
	}
}

func cePassingReq() hdf.EvaluatedRequirement {
	return ceValid(stMakeRequirement(func(r *hdf.EvaluatedRequirement) {
		r.Impact = 0.5
		r.Results = []hdf.RequirementResult{stMakeResult(hdf.Passed)}
	}))
}

// ceValid fills the schema-required minimums the shared builders omit
// (descriptions minItems + default label) so emitted events schema-validate.
func ceValid(req hdf.EvaluatedRequirement) hdf.EvaluatedRequirement {
	if len(req.Descriptions) == 0 {
		req.Descriptions = []hdf.Description{{Label: "default", Data: "test description"}}
	}
	return req
}

// assertValidEvent marshals the event and runs it through the real schema validator.
func assertValidEvent(t *testing.T, ev *hdf.HDFRequirementChangeEvent) {
	t.Helper()
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	result := validators.ValidateRequirementChangeEvent(raw)
	assert.True(t, result.Valid, "emitted event must be schema-valid: %v", result.Errors)
}

func TestChangeEventFromPrevious_NoChangeReturnsNil(t *testing.T) {
	req := ceValid(ecFailingReq()) // failed @ 0.5 → checksum matches cePrevFailing
	ev := ChangeEventFromPrevious(cePrevFailing(), &req, nil, ceInputs())
	assert.Nil(t, ev, "matching checksum must emit no event")
}

func TestChangeEventFromPrevious_NewKey(t *testing.T) {
	req := cePassingReq()
	ev := ChangeEventFromPrevious(nil, &req, nil, ceInputs())
	require.NotNil(t, ev)
	assert.Equal(t, hdf.EventRequirementStateNew, ev.State)
	assert.Nil(t, ev.Before, "no prior posture for a new key")
	assert.Nil(t, ev.PriorChecksum, "chain start")
	require.NotNil(t, ev.After)
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_AbsentKey(t *testing.T) {
	ev := ChangeEventFromPrevious(cePrevFailing(), nil, nil, ceInputs())
	require.NotNil(t, ev)
	assert.Equal(t, hdf.EventRequirementStateAbsent, ev.State)
	assert.Nil(t, ev.After, "absent has no after by definition")
	before, ok := ev.Before.(map[string]interface{})
	require.True(t, ok, "before must be the thin projection")
	assert.Equal(t, "failed", before["effectiveStatus"])
	assert.InDelta(t, 0.5, before["effectiveImpact"].(float64), 1e-9)
	prior, ok := ev.PriorChecksum.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, ecVectorFailedHalf, prior["value"])
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_BothNilReturnsNil(t *testing.T) {
	assert.Nil(t, ChangeEventFromPrevious(nil, nil, nil, ceInputs()))
}

func TestChangeEventFromPrevious_FailedToPassedIsFixed(t *testing.T) {
	req := cePassingReq()
	ev := ChangeEventFromPrevious(cePrevFailing(), &req, nil, ceInputs())
	require.NotNil(t, ev)
	assert.Equal(t, hdf.EventRequirementStateFixed, ev.State)
	prior, ok := ev.PriorChecksum.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, ecVectorFailedHalf, prior["value"], "priorChecksum links the chain")
	before, ok := ev.Before.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, map[string]interface{}{"effectiveStatus": "failed", "effectiveImpact": 0.5}, before)
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_PassedToFailedIsRegressed(t *testing.T) {
	prev := &KeyState{
		EffectiveStatus: "passed",
		EffectiveImpact: 0.5,
		Checksum:        hdf.Checksum{Algorithm: hdf.Sha256, Value: ecVectorPassedHalf},
	}
	req := ceValid(ecFailingReq())
	ev := ChangeEventFromPrevious(prev, &req, nil, ceInputs())
	require.NotNil(t, ev)
	assert.Equal(t, hdf.EventRequirementStateRegressed, ev.State)
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_ImpactOnlyChangeIsUpdated(t *testing.T) {
	// Status stays failed; a risk adjustment drops effective impact.
	req := ceValid(ecFailingReq())
	req.StatusOverrides = []hdf.StatusOverride{{
		Type:      hdf.RiskAdjustment,
		Impact:    &hdf.ImpactOverride{Value: 0.2},
		Reason:    "environmental adjustment",
		AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
		AppliedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
	}}
	ev := ChangeEventFromPrevious(cePrevFailing(), &req, nil, ceInputs())
	require.NotNil(t, ev)
	assert.Equal(t, hdf.EventRequirementStateUpdated, ev.State, "same status, changed impact → updated")
	assert.Contains(t, ev.ChangeReasons, hdf.EventChangeReasonImpactChanged,
		"impact delta is provable from thin prev state")
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_EnvelopeEchoesInputs(t *testing.T) {
	req := cePassingReq()
	in := ceInputs()
	schemaRef := "https://mitre.github.io/hdf-libs/schemas/hdf-requirement-change-event/v3.4.0"
	in.SchemaRef = schemaRef
	ev := ChangeEventFromPrevious(cePrevFailing(), &req, nil, in)
	require.NotNil(t, ev)
	assert.Equal(t, in.EventID, ev.EventID)
	assert.Equal(t, in.Source, ev.Source)
	assert.Equal(t, in.Sequence, ev.Sequence)
	assert.Equal(t, in.SystemRef, ev.SystemRef)
	assert.Equal(t, in.ComponentID, ev.ComponentID)
	assert.Equal(t, in.RequirementID, ev.RequirementID)
	assert.Equal(t, in.Timestamp, ev.Timestamp)
	require.NotNil(t, ev.SchemaRef)
	assert.Equal(t, schemaRef, *ev.SchemaRef)
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_RicherReasonsWithPrevRequirement(t *testing.T) {
	// Waiver added: failed → passed via override. With the full prior requirement
	// available, the classifier attributes the flip to the override, not a rescan.
	prevReq := ceValid(ecFailingReq())
	newReq := ceValid(ecFailingReq())
	newReq.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
		Type      string
		Status    hdf.ResultStatus
		Reason    string
		AppliedAt time.Time
		ExpiresAt time.Time
	}{Type: "waiver", Status: hdf.Passed})}

	ev := ChangeEventFromPrevious(cePrevFailing(), &newReq, &prevReq, ceInputs())
	require.NotNil(t, ev)
	assert.Equal(t, hdf.EventRequirementStateFixed, ev.State)
	assert.Contains(t, ev.ChangeReasons, hdf.EventChangeReasonOverrideAdded)
	assert.NotContains(t, ev.ChangeReasons, hdf.EventChangeReasonResultChanged,
		"results are identical; the override is the cause")
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_FiltersNonEventReasons(t *testing.T) {
	// A title change makes the batch classifier emit metadataChanged, which is
	// NOT in the event vocabulary and must be filtered out.
	prevReq := ceValid(ecFailingReq())
	newReq := cePassingReq()
	newReq.Title = stPtrString("Renamed control title")

	ev := ChangeEventFromPrevious(cePrevFailing(), &newReq, &prevReq, ceInputs())
	require.NotNil(t, ev)
	for _, r := range ev.ChangeReasons {
		assert.NotEqual(t, "metadataChanged", string(r),
			"batch-only reasons must not reach the wire")
	}
	assert.Contains(t, ev.ChangeReasons, hdf.EventChangeReasonResultChanged)
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_MappedImpactReasons(t *testing.T) {
	t.Run("effectiveImpactChanged maps to impactChanged exactly once", func(t *testing.T) {
		prevReq := ceValid(ecFailingReq())
		newReq := ceValid(ecFailingReq())
		newReq.StatusOverrides = []hdf.StatusOverride{{
			Type:      hdf.RiskAdjustment,
			Impact:    &hdf.ImpactOverride{Value: 0.2},
			Reason:    "environmental adjustment",
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "admin"},
			AppliedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		}}
		materialized := 0.2
		newReq.EffectiveImpact = &materialized

		ev := ChangeEventFromPrevious(cePrevFailing(), &newReq, &prevReq, ceInputs())
		require.NotNil(t, ev)
		assert.Contains(t, ev.ChangeReasons, hdf.EventChangeReasonOverrideAdded)
		count := 0
		for _, r := range ev.ChangeReasons {
			if r == hdf.EventChangeReasonImpactChanged {
				count++
			}
		}
		assert.Equal(t, 1, count, "effectiveImpactChanged must map to a single impactChanged")
		assertValidEvent(t, ev)
	})

	t.Run("base impact change maps to impactChanged", func(t *testing.T) {
		prevReq := ceValid(ecFailingReq())
		newReq := ceValid(ecFailingReq())
		newReq.Impact = 0.3

		ev := ChangeEventFromPrevious(cePrevFailing(), &newReq, &prevReq, ceInputs())
		require.NotNil(t, ev)
		assert.Contains(t, ev.ChangeReasons, hdf.EventChangeReasonImpactChanged)
		assertValidEvent(t, ev)
	})
}

func TestChangeEventFromPrevious_OverrideExpiredAcrossWindow(t *testing.T) {
	// The marquee triage case: a waiver lapsed between observations. Results
	// are identical scans; only the expiry crossing the observation window
	// explains the regression. Deliberately-past expiresAt asserts expiry.
	waived := func() hdf.EvaluatedRequirement {
		req := ceValid(ecFailingReq())
		req.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
			Type      string
			Status    hdf.ResultStatus
			Reason    string
			AppliedAt time.Time
			ExpiresAt time.Time
		}{Type: "waiver", Status: hdf.Passed, ExpiresAt: time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)})}
		return req
	}
	prevReq := waived()
	newReq := waived()

	prev := &KeyState{
		EffectiveStatus: "passed",
		EffectiveImpact: 0.5,
		Checksum:        hdf.Checksum{Algorithm: hdf.Sha256, Value: "d11c074ab9131807816013a71d986f1ceb2e5871a8a01dee4043391b7a6bf37b"},
	}
	in := ceInputs()
	in.PrevReferenceTimestamp = "2026-07-20T00:00:00Z"
	in.ReferenceTimestamp = "2026-07-22T14:03:11Z"

	ev := ChangeEventFromPrevious(prev, &newReq, &prevReq, in)
	require.NotNil(t, ev)
	assert.Equal(t, hdf.EventRequirementStateRegressed, ev.State)
	assert.Contains(t, ev.ChangeReasons, hdf.EventChangeReasonOverrideExpired)
	assert.NotContains(t, ev.ChangeReasons, hdf.EventChangeReasonResultChanged,
		"identical scans; the lapsed waiver is the cause")
	assertValidEvent(t, ev)
}

func TestChangeEventFromPrevious_OverrideRemoved(t *testing.T) {
	prevReq := ceValid(ecFailingReq())
	prevReq.StatusOverrides = []hdf.StatusOverride{stMakeOverride(struct {
		Type      string
		Status    hdf.ResultStatus
		Reason    string
		AppliedAt time.Time
		ExpiresAt time.Time
	}{Type: "waiver", Status: hdf.Passed})}
	newReq := ceValid(ecFailingReq())

	prev := &KeyState{
		EffectiveStatus: "passed",
		EffectiveImpact: 0.5,
		Checksum:        hdf.Checksum{Algorithm: hdf.Sha256, Value: "d11c074ab9131807816013a71d986f1ceb2e5871a8a01dee4043391b7a6bf37b"},
	}
	ev := ChangeEventFromPrevious(prev, &newReq, &prevReq, ceInputs())
	require.NotNil(t, ev)
	assert.Equal(t, hdf.EventRequirementStateRegressed, ev.State)
	assert.Contains(t, ev.ChangeReasons, hdf.EventChangeReasonOverrideRemoved)
	assertValidEvent(t, ev)
}
