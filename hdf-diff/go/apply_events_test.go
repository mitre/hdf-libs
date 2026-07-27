package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func aeInputs() ApplyInputs {
	return ApplyInputs{
		Generator: hdf.Generator{Name: "conmon-reconciler-test", Version: "0.0.1"},
		SeedURI:   "seed.hdf.json",
		Source:    "inspec://fixture/scan",
	}
}

// aeLoadFixture reads a shared fixture document.
func aeLoadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesDir(t), name))
	require.NoError(t, err)
	return data
}

// aeDeriveStream builds the event stream between two same-target documents
// using the real detection kernel — the derive() side of the §6 parity law.
// Sequences are assigned deterministically (new-doc order, then removed keys
// sorted by id).
func aeDeriveStream(t *testing.T, seedBytes, nextBytes []byte) []*hdf.HDFRequirementChangeEvent {
	t.Helper()
	var seedDoc, nextDoc hdf.HDFResults
	require.NoError(t, json.Unmarshal(seedBytes, &seedDoc))
	require.NoError(t, json.Unmarshal(nextBytes, &nextDoc))

	refTs := "2026-07-22T14:03:11Z"
	if nextDoc.Timestamp != nil {
		refTs = nextDoc.Timestamp.UTC().Format(time.RFC3339Nano)
	}
	prevRefTs := refTs
	if seedDoc.Timestamp != nil {
		prevRefTs = seedDoc.Timestamp.UTC().Format(time.RFC3339Nano)
	}

	type prevEntry struct {
		state KeyState
		req   hdf.EvaluatedRequirement
	}
	prevByKey := map[string]prevEntry{}
	for _, b := range seedDoc.Baselines {
		for _, r := range b.Requirements {
			cs := ComputeEffectiveChecksum(r, refTs)
			require.NotNil(t, cs)
			prevByKey[r.ID] = prevEntry{
				state: KeyState{
					EffectiveStatus: ComputeEffectiveStatus(r, refTs),
					EffectiveImpact: ComputeEffectiveImpact(r, refTs),
					Checksum:        *cs,
				},
				req: r,
			}
		}
	}

	// Events occur when the next document was observed — its scan time.
	occurred, err := time.Parse(time.RFC3339, refTs)
	require.NoError(t, err)
	var events []*hdf.HDFRequirementChangeEvent
	seq := int64(0)
	mkInputs := func(id string) EventInputs {
		seq++
		return EventInputs{
			EventID:                fmt.Sprintf("0190f6f2-0000-7000-8000-%012d", seq),
			Source:                 "inspec://fixture/scan",
			Sequence:               seq,
			SystemRef:              "fixture.hdf-system.json",
			ComponentID:            "6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60",
			RequirementID:          id,
			Timestamp:              occurred,
			ReferenceTimestamp:     refTs,
			PrevReferenceTimestamp: prevRefTs,
		}
	}

	for _, b := range nextDoc.Baselines {
		for i := range b.Requirements {
			r := b.Requirements[i]
			var prevState *KeyState
			var prevReq *hdf.EvaluatedRequirement
			if entry, ok := prevByKey[r.ID]; ok {
				s, q := entry.state, entry.req
				prevState, prevReq = &s, &q
				delete(prevByKey, r.ID)
			}
			if ev := ChangeEventFromPrevious(prevState, &r, prevReq, mkInputs(r.ID)); ev != nil {
				events = append(events, ev)
			}
		}
	}
	removed := make([]string, 0, len(prevByKey))
	for id := range prevByKey {
		removed = append(removed, id)
	}
	sort.Strings(removed)
	for _, id := range removed {
		entry := prevByKey[id]
		s, q := entry.state, entry.req
		if ev := ChangeEventFromPrevious(&s, nil, &q, mkInputs(id)); ev != nil {
			events = append(events, ev)
		}
	}
	return events
}

// aeRequirementsByID extracts every requirement from a results document,
// keyed by id, canonically marshaled for comparison.
func aeRequirementsByID(t *testing.T, docBytes []byte) map[string]string {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(docBytes, &doc))
	out := map[string]string{}
	baselines, _ := doc["baselines"].([]interface{})
	for _, bRaw := range baselines {
		b, _ := bRaw.(map[string]interface{})
		reqs, _ := b["requirements"].([]interface{})
		for _, rRaw := range reqs {
			r, _ := rRaw.(map[string]interface{})
			id, _ := r["id"].(string)
			raw, err := json.Marshal(r)
			require.NoError(t, err)
			out[id] = string(raw)
		}
	}
	return out
}

// aeMaskVolatile applies the §6 documented mask to one requirement map:
// per-run volatile result fields (startTime, runTime) — legitimate residue on
// UNCHANGED requirements, which honestly carry the seed's last observation.
func aeMaskVolatile(req map[string]interface{}) {
	results, _ := req["results"].([]interface{})
	for _, rRaw := range results {
		if r, ok := rRaw.(map[string]interface{}); ok {
			delete(r, "startTime")
			delete(r, "runTime")
		}
	}
}

// aeNormalize canonicalizes a requirement map for comparison: empty optional
// arrays at the requirement level are equivalent to the field being absent
// (the Go kernel's typed after-payload canonicalizes them away via
// omitempty; the schema treats both identically).
func aeNormalize(req map[string]interface{}) {
	for k, v := range req {
		if arr, ok := v.([]interface{}); ok && len(arr) == 0 && k != "descriptions" && k != "results" {
			delete(req, k)
		}
	}
}

func aeParityCheck(t *testing.T, seedName, nextName string) {
	t.Helper()
	seed := aeLoadFixture(t, seedName)
	next := aeLoadFixture(t, nextName)
	events := aeDeriveStream(t, seed, next)

	changed := map[string]bool{}
	for _, ev := range events {
		changed[ev.RequirementID] = true
	}

	result, err := ApplyChangeEvents(seed, events, aeInputs())
	require.NoError(t, err)
	assert.Empty(t, result.Warnings, "a complete derived stream must verify cleanly")

	got := aeRequirementsByID(t, result.Results)
	want := aeRequirementsByID(t, next)
	require.Equal(t, len(want), len(got), "requirement count must match the rescan")
	for id, wantRaw := range want {
		gotRaw, ok := got[id]
		require.True(t, ok, "requirement %s missing from reassembled doc", id)

		var wantReq, gotReq map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(wantRaw), &wantReq))
		require.NoError(t, json.Unmarshal([]byte(gotRaw), &gotReq))
		aeNormalize(wantReq)
		aeNormalize(gotReq)
		if !changed[id] {
			// Unchanged keys: the reconciled doc honestly reports the last
			// observation; only per-run volatile fields may differ (§6 mask).
			aeMaskVolatile(wantReq)
			aeMaskVolatile(gotReq)
		}
		assert.Equal(t, wantReq, gotReq, "requirement %s must match the rescan content", id)
	}

	validation := validators.ValidateResults(result.Results)
	assert.True(t, validation.Valid, "reassembled doc must be schema-valid: %v", validation.Errors)
}

func TestApplyChangeEvents_ReassemblyParity_ScanPair(t *testing.T) {
	aeParityCheck(t, "scan-before.json", "scan-after.json")
}

func TestApplyChangeEvents_ReassemblyParity_OverridePair(t *testing.T) {
	// Card AC named the ubuntu pair, but those fixtures are legacy-shaped
	// (no baselines[].requirements) and unusable for a v3 reassembly law.
	// scan-before → scan-with-override exercises the override-driven change
	// path plus heavy tombstoning (four keys leave scope).
	aeParityCheck(t, "scan-before.json", "scan-with-override.json")
}

func TestApplyChangeEvents_DerivationBlockAndGenerator(t *testing.T) {
	seed := aeLoadFixture(t, "scan-before.json")
	next := aeLoadFixture(t, "scan-after.json")
	events := aeDeriveStream(t, seed, next)

	result, err := ApplyChangeEvents(seed, events, aeInputs())
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(result.Results, &doc))

	gen, ok := doc["generator"].(map[string]interface{})
	require.True(t, ok, "reconciled doc must carry the reconciler generator")
	assert.Equal(t, "conmon-reconciler-test", gen["name"])

	deriv, ok := doc["derivation"].(map[string]interface{})
	require.True(t, ok, "reconciled doc must carry the derivation block")
	seedRef := deriv["seed"].(map[string]interface{})
	assert.Equal(t, "seed.hdf.json", seedRef["uri"])
	cs := seedRef["checksum"].(map[string]interface{})
	assert.Equal(t, "sha256", cs["algorithm"])
	assert.Len(t, cs["value"], 64)
	assert.Equal(t, float64(len(events)), deriv["eventsApplied"])
	var maxSeq int64
	for _, ev := range events {
		if ev.Sequence > maxSeq {
			maxSeq = ev.Sequence
		}
	}
	assert.Equal(t, float64(maxSeq), deriv["throughSequence"],
		"watermark is the highest sequence seen (unchanged keys still consume sequence numbers)")
	assert.Equal(t, "inspec://fixture/scan", deriv["source"])
	assert.Equal(t, "2024-02-01T00:00:00Z", deriv["asOf"], "asOf is the next scan's observation time")
}

func TestApplyChangeEvents_Idempotent(t *testing.T) {
	seed := aeLoadFixture(t, "scan-before.json")
	next := aeLoadFixture(t, "scan-after.json")
	events := aeDeriveStream(t, seed, next)

	once, err := ApplyChangeEvents(seed, events, aeInputs())
	require.NoError(t, err)
	twice, err := ApplyChangeEvents(seed, append(append([]*hdf.HDFRequirementChangeEvent{}, events...), events...), aeInputs())
	require.NoError(t, err)
	assert.Equal(t, string(once.Results), string(twice.Results),
		"duplicate delivery (same source+eventId) must not change the output")
}

func TestApplyChangeEvents_OrderInvariant(t *testing.T) {
	seed := aeLoadFixture(t, "scan-before.json")
	next := aeLoadFixture(t, "scan-after.json")
	events := aeDeriveStream(t, seed, next)

	reversed := make([]*hdf.HDFRequirementChangeEvent, len(events))
	for i, ev := range events {
		reversed[len(events)-1-i] = ev
	}

	inOrder, err := ApplyChangeEvents(seed, events, aeInputs())
	require.NoError(t, err)
	shuffled, err := ApplyChangeEvents(seed, reversed, aeInputs())
	require.NoError(t, err)
	assert.Equal(t, string(inOrder.Results), string(shuffled.Results),
		"delivery order must not affect the fold (sequence is the only ordering authority)")
}

// aeTwoStepChain builds seed bytes plus a two-event chain for one key:
// failed → passed (fixed, seq 1) → failed (regressed, seq 2), with event 2's
// priorChecksum linking to event 1's after-posture.
func aeTwoStepChain(t *testing.T) (seed []byte, e1, e2 *hdf.HDFRequirementChangeEvent) {
	t.Helper()
	seedJSON := `{
	  "timestamp": "2026-07-22T00:00:00Z",
	  "baselines": [{"name": "chain", "requirements": [
	    {"id": "SV-100001", "impact": 0.5, "tags": {},
	     "descriptions": [{"label": "default", "data": "test description"}],
	     "results": [{"status": "failed", "codeDesc": "test", "startTime": "2025-01-01T00:00:00Z"}]}
	  ]}],
	  "statistics": {"duration": 0.1}
	}`
	refTs := "2026-07-22T14:03:11Z"

	seedReq := ceValid(ecFailingReq())
	seedReq.ID = "SV-100001"
	seedCS := ComputeEffectiveChecksum(seedReq, refTs)
	require.NotNil(t, seedCS)

	passing := cePassingReq()
	passing.ID = "SV-100001"
	in1 := ceInputs()
	in1.RequirementID = "SV-100001"
	in1.Sequence = 1
	in1.EventID = "0190f6f2-0000-7000-8000-000000000001"
	in1.ReferenceTimestamp = refTs
	e1 = ChangeEventFromPrevious(&KeyState{
		EffectiveStatus: "failed", EffectiveImpact: 0.5, Checksum: *seedCS,
	}, &passing, &seedReq, in1)
	require.NotNil(t, e1)

	afterCS := ComputeEffectiveChecksum(passing, refTs)
	require.NotNil(t, afterCS)
	failingAgain := ceValid(ecFailingReq())
	failingAgain.ID = "SV-100001"
	in2 := in1
	in2.Sequence = 2
	in2.EventID = "0190f6f2-0000-7000-8000-000000000002"
	e2 = ChangeEventFromPrevious(&KeyState{
		EffectiveStatus: "passed", EffectiveImpact: 0.5, Checksum: *afterCS,
	}, &failingAgain, &passing, in2)
	require.NotNil(t, e2)

	return []byte(seedJSON), e1, e2
}

func TestApplyChangeEvents_ChainVerification(t *testing.T) {
	seed, e1, e2 := aeTwoStepChain(t)

	t.Run("complete chain verifies cleanly", func(t *testing.T) {
		result, err := ApplyChangeEvents(seed, []*hdf.HDFRequirementChangeEvent{e1, e2}, aeInputs())
		require.NoError(t, err)
		assert.Empty(t, result.Warnings)
	})

	t.Run("missing link is detected but still applied last-value-wins", func(t *testing.T) {
		full, err := ApplyChangeEvents(seed, []*hdf.HDFRequirementChangeEvent{e1, e2}, aeInputs())
		require.NoError(t, err)
		gapped, err := ApplyChangeEvents(seed, []*hdf.HDFRequirementChangeEvent{e2}, aeInputs())
		require.NoError(t, err)

		require.Len(t, gapped.Warnings, 1)
		assert.Equal(t, "chainGap", gapped.Warnings[0].Kind)
		assert.Equal(t, "SV-100001", gapped.Warnings[0].RequirementID)

		// The winning posture is identical either way — only the derivation
		// metadata (eventsApplied) may differ.
		fullReqs := aeRequirementsByID(t, full.Results)
		gappedReqs := aeRequirementsByID(t, gapped.Results)
		assert.Equal(t, fullReqs, gappedReqs)
	})
}

func TestApplyChangeEvents_Anomalies(t *testing.T) {
	seed, e1, _ := aeTwoStepChain(t)

	t.Run("absent for an unknown key warns and no-ops", func(t *testing.T) {
		in := ceInputs()
		in.RequirementID = "SV-999999"
		in.Sequence = 7
		ghost := ChangeEventFromPrevious(&KeyState{
			EffectiveStatus: "failed", EffectiveImpact: 0.5,
			Checksum: hdf.Checksum{Algorithm: hdf.Sha256, Value: ecVectorFailedHalf},
		}, nil, nil, in)
		require.NotNil(t, ghost)

		result, err := ApplyChangeEvents(seed, []*hdf.HDFRequirementChangeEvent{ghost}, aeInputs())
		require.NoError(t, err)
		require.Len(t, result.Warnings, 1)
		assert.Equal(t, "absentUnknown", result.Warnings[0].Kind)
		assert.Len(t, aeRequirementsByID(t, result.Results), 1, "seed requirement untouched")
	})

	t.Run("new for an existing key warns and replaces", func(t *testing.T) {
		passing := cePassingReq()
		passing.ID = "SV-100001"
		in := ceInputs()
		in.RequirementID = "SV-100001"
		in.Sequence = 9
		fresh := ChangeEventFromPrevious(nil, &passing, nil, in)
		require.NotNil(t, fresh)

		result, err := ApplyChangeEvents(seed, []*hdf.HDFRequirementChangeEvent{fresh}, aeInputs())
		require.NoError(t, err)
		require.Len(t, result.Warnings, 1)
		assert.Equal(t, "newOnExisting", result.Warnings[0].Kind)
	})

	t.Run("empty event batch is a seed passthrough with lineage", func(t *testing.T) {
		result, err := ApplyChangeEvents(seed, nil, aeInputs())
		require.NoError(t, err)
		assert.Empty(t, result.Warnings)
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(result.Results, &doc))
		deriv := doc["derivation"].(map[string]interface{})
		assert.Equal(t, float64(0), deriv["eventsApplied"])
		assert.Equal(t, "2026-07-22T00:00:00Z", deriv["asOf"], "falls back to the seed timestamp")
	})

	_ = e1
}
