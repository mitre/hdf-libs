package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The table read here is also read by test/shared-event-cases.test.ts, so both kernels
// are asserted against ONE definition of what a requirement id's entries fold to, what
// event that produces, and what applying it back leaves in the document.

type sharedFold struct {
	EffectiveStatus string  `json:"effectiveStatus"`
	EffectiveImpact float64 `json:"effectiveImpact"`
	Checksum        string  `json:"checksum"`
}

type sharedEventExpectation struct {
	State         string      `json:"state"`
	AfterCount    int         `json:"afterCount"`
	ChangeReasons []string    `json:"changeReasons"`
	Before        *sharedFold `json:"before"`
}

type sharedFoldedDiff struct {
	State              string   `json:"state"`
	OldEffectiveStatus *string  `json:"oldEffectiveStatus"`
	NewEffectiveStatus *string  `json:"newEffectiveStatus"`
	OldImpact          *float64 `json:"oldImpact"`
	NewImpact          *float64 `json:"newImpact"`
}

type sharedApplyExpectation struct {
	Baselines [][]string `json:"baselines"`
	Warnings  []string   `json:"warnings"`
}

type sharedEventCase struct {
	Name                string                       `json:"name"`
	Why                 string                       `json:"why"`
	Prev                [][]hdf.EvaluatedRequirement `json:"prev"`
	Next                []hdf.EvaluatedRequirement   `json:"next"`
	PrevFold            *sharedFold                  `json:"prevFold"`
	NextFold            *sharedFold                  `json:"nextFold"`
	SingleEntryChecksum bool                         `json:"singleEntryChecksum"`
	Event               *sharedEventExpectation      `json:"event"`
	Applied             sharedApplyExpectation       `json:"applied"`
	FoldedDiff          *sharedFoldedDiff            `json:"foldedDiff"`
}

type sharedEventTable struct {
	Inputs struct {
		EventID            string `json:"eventId"`
		Source             string `json:"source"`
		Sequence           int64  `json:"sequence"`
		SystemRef          string `json:"systemRef"`
		ComponentID        string `json:"componentId"`
		RequirementID      string `json:"requirementId"`
		Timestamp          string `json:"timestamp"`
		ReferenceTimestamp string `json:"referenceTimestamp"`
	} `json:"inputs"`
	SeedTimestamp string            `json:"seedTimestamp"`
	Cases         []sharedEventCase `json:"cases"`
}

func TestSharedDuplicateIDEventCases(t *testing.T) {
	raw, err := os.ReadFile("../testdata/duplicate-id-event-cases.json")
	require.NoError(t, err)
	var table sharedEventTable
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)

	occurred, err := time.Parse(time.RFC3339, table.Inputs.Timestamp)
	require.NoError(t, err)
	ref := table.Inputs.ReferenceTimestamp

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			prevEntries := []hdf.EvaluatedRequirement{}
			for _, baseline := range tc.Prev {
				prevEntries = append(prevEntries, baseline...)
			}

			prevState := FoldEffectiveState(prevEntries, ref)
			assertFold(t, tc.PrevFold, prevState, "prev fold: "+tc.Why)
			assertFold(t, tc.NextFold, FoldEffectiveState(tc.Next, ref), "next fold: "+tc.Why)

			if tc.SingleEntryChecksum {
				require.Len(t, prevEntries, 1)
				own := ComputeEffectiveChecksum(prevEntries[0], ref)
				require.NotNil(t, own)
				assert.Equal(t, own.Value, prevState.Checksum.Value,
					"one entry must keep exactly its own effective checksum: "+tc.Why)
			}

			ev := ChangeEventFromPrevious(prevState, tc.Next, prevEntries, EventInputs{
				EventID:            table.Inputs.EventID,
				Source:             table.Inputs.Source,
				Sequence:           table.Inputs.Sequence,
				SystemRef:          table.Inputs.SystemRef,
				ComponentID:        table.Inputs.ComponentID,
				RequirementID:      table.Inputs.RequirementID,
				Timestamp:          occurred,
				ReferenceTimestamp: ref,
			})
			assertEvent(t, tc, ev)

			seed, err := json.Marshal(map[string]interface{}{
				"timestamp": table.SeedTimestamp,
				"baselines": seedBaselines(tc.Prev),
			})
			require.NoError(t, err)
			events := []*hdf.HDFRequirementChangeEvent{}
			if ev != nil {
				events = append(events, ev)
			}
			result, err := ApplyChangeEvents(seed, events, ApplyInputs{
				Generator: hdf.Generator{Name: "shared-case-table", Version: "0.0.0"},
				SeedURI:   "memory://seed",
				Source:    table.Inputs.Source,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.Applied.Baselines, appliedTitles(t, result.Results), "applied: "+tc.Why)
			assert.Equal(t, tc.Applied.Warnings, warningKinds(result.Warnings), "warnings: "+tc.Why)

			folded, err := FoldChangeEventsIntoComparison(seed, events)
			require.NoError(t, err)
			assertFoldedDiff(t, tc, folded.Comparison.RequirementDiffs)
		})
	}
}

func assertFold(t *testing.T, want *sharedFold, got *KeyState, why string) {
	t.Helper()
	if want == nil {
		assert.Nil(t, got, why)
		return
	}
	require.NotNil(t, got, why)
	assert.Equal(t, want.EffectiveStatus, got.EffectiveStatus, why)
	assert.InDelta(t, want.EffectiveImpact, got.EffectiveImpact, 1e-9, why)
	assert.Equal(t, want.Checksum, got.Checksum.Value, why)
}

func assertEvent(t *testing.T, tc sharedEventCase, ev *hdf.HDFRequirementChangeEvent) {
	t.Helper()
	if tc.Event == nil {
		assert.Nil(t, ev, "no event expected: "+tc.Why)
		return
	}
	require.NotNil(t, ev, tc.Why)
	assert.Equal(t, tc.Event.State, string(ev.State), tc.Why)
	assert.Len(t, ev.After, tc.Event.AfterCount, "after[] carries every entry: "+tc.Why)

	reasons := []string{}
	for _, r := range ev.ChangeReasons {
		reasons = append(reasons, string(r))
	}
	assert.Equal(t, tc.Event.ChangeReasons, reasons, tc.Why)

	if tc.Event.Before == nil {
		assert.Nil(t, ev.Before, "before is null exactly at chain start: "+tc.Why)
		assert.Nil(t, ev.PriorChecksum, tc.Why)
		return
	}
	before, ok := ev.Before.(map[string]interface{})
	require.True(t, ok, tc.Why)
	assert.Equal(t, tc.Event.Before.EffectiveStatus, before["effectiveStatus"], tc.Why)
	assert.InDelta(t, tc.Event.Before.EffectiveImpact, before["effectiveImpact"], 1e-9, tc.Why)
	// The chain link is the prior FOLDED state, which the table pins literally.
	require.NotNil(t, tc.PrevFold, tc.Why)
	assert.Equal(t, tc.PrevFold.Checksum, eventPriorValue(ev), tc.Why)
}

func seedBaselines(prev [][]hdf.EvaluatedRequirement) []interface{} {
	baselines := []interface{}{}
	for i, entries := range prev {
		reqs := entries
		if reqs == nil {
			reqs = []hdf.EvaluatedRequirement{}
		}
		baselines = append(baselines, map[string]interface{}{
			"name":         fmt.Sprintf("baseline-%d", i),
			"requirements": reqs,
		})
	}
	return baselines
}

func appliedTitles(t *testing.T, results []byte) [][]string {
	t.Helper()
	var doc struct {
		Baselines []struct {
			Requirements []struct {
				Title *string `json:"title"`
			} `json:"requirements"`
		} `json:"baselines"`
	}
	require.NoError(t, json.Unmarshal(results, &doc))
	titles := [][]string{}
	for _, baseline := range doc.Baselines {
		names := []string{}
		for _, req := range baseline.Requirements {
			if req.Title != nil {
				names = append(names, *req.Title)
			}
		}
		titles = append(titles, names)
	}
	return titles
}

func warningKinds(warnings []ApplyWarning) []string {
	kinds := []string{}
	for _, w := range warnings {
		kinds = append(kinds, w.Kind)
	}
	return kinds
}

func assertFoldedDiff(t *testing.T, tc sharedEventCase, diffs []RequirementDiff) {
	t.Helper()
	if tc.FoldedDiff == nil {
		assert.Empty(t, diffs, "no event, so no requirementDiff: "+tc.Why)
		return
	}
	// ONE diff per key however many entries the id carries, because the event key is the
	// requirement (ADR-0005 §1).
	require.Len(t, diffs, 1, tc.Why)
	got := diffs[0]
	assert.Equal(t, tc.FoldedDiff.State, string(got.State), tc.Why)
	assert.Equal(t, derefString(tc.FoldedDiff.OldEffectiveStatus), got.OldEffectiveStatus, "old status: "+tc.Why)
	assert.Equal(t, derefString(tc.FoldedDiff.NewEffectiveStatus), got.NewEffectiveStatus, "new status: "+tc.Why)
	assertImpact(t, tc.FoldedDiff.OldImpact, got.OldImpact, "old impact: "+tc.Why)
	assertImpact(t, tc.FoldedDiff.NewImpact, got.NewImpact, "new impact: "+tc.Why)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func assertImpact(t *testing.T, want, got *float64, why string) {
	t.Helper()
	if want == nil {
		assert.Nil(t, got, why)
		return
	}
	require.NotNil(t, got, why)
	assert.InDelta(t, *want, *got, 1e-9, why)
}
