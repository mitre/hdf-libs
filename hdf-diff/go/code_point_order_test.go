package diff

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orderVectors loads the identifier-order table shared with test/order-vectors.ts:
// both languages must emit identifiers in the same order, or the same inputs give
// different comparison bytes.
func orderVectors(t *testing.T) (ids, codePointOrder []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "code-point-order-vectors.json"))
	require.NoError(t, err, "the shared table is the contract")
	var table struct {
		IDs            []string `json:"ids"`
		CodePointOrder []string `json:"codePointOrder"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.IDs, "a pass must not mean an empty table")
	return table.IDs, table.CodePointOrder
}

// orderResultsJSON is the twin of orderResultsDoc in test/order-vectors.ts.
func orderResultsJSON(t *testing.T, status string, order []string) []byte {
	t.Helper()
	reqs := make([]any, 0, len(order))
	for _, id := range order {
		reqs = append(reqs, map[string]any{
			"id": id, "title": "Check " + id, "impact": 0.5, "tags": map[string]any{},
			"descriptions": []any{map[string]any{"label": "default", "data": "test"}},
			"results":      []any{map[string]any{"status": status, "codeDesc": "test", "startTime": "2024-01-01T00:00:00Z"}},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"timestamp": "2024-01-01T00:00:00Z",
		"baselines": []any{map[string]any{
			"name": "order-baseline", "version": "1.0.0", "groups": []any{}, "supports": []any{},
			"requirements": reqs,
		}},
	})
	require.NoError(t, err)
	return raw
}

func orderResults(t *testing.T, status string, order []string) hdf.HDFResults {
	t.Helper()
	var doc hdf.HDFResults
	require.NoError(t, json.Unmarshal(orderResultsJSON(t, status, order), &doc))
	return doc
}

func reversed(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

func diffIDs(diffs []RequirementDiff) []string {
	out := make([]string, 0, len(diffs))
	for _, d := range diffs {
		out = append(out, d.ID)
	}
	return out
}

func TestOrderVectors_AreNotAlreadySorted(t *testing.T) {
	ids, want := orderVectors(t)
	assert.NotEqual(t, want, ids)
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	assert.Equal(t, want, sorted, "codePointOrder is Go's byte order of ids")
}

func TestOrder_TemporalRequirementDiffs(t *testing.T) {
	ids, want := orderVectors(t)
	comp := mustDiffHdf(t, orderResults(t, "passed", ids), []hdf.HDFResults{orderResults(t, "failed", reversed(ids))}, defaultOpts())
	assert.Equal(t, want, diffIDs(comp.RequirementDiffs))
}

func TestOrder_FleetRequirementDiffs(t *testing.T) {
	ids, want := orderVectors(t)
	comp := mustDiffHdf(t, orderResults(t, "passed", ids),
		[]hdf.HDFResults{orderResults(t, "failed", ids), orderResults(t, "passed", ids)}, fleetOpts())
	type key struct {
		id  string
		src int
	}
	var got, expected []key
	for _, d := range comp.RequirementDiffs {
		require.NotNil(t, d.SourceIndex)
		got = append(got, key{d.ID, *d.SourceIndex})
	}
	for _, id := range want {
		expected = append(expected, key{id, 1}, key{id, 2})
	}
	assert.Equal(t, expected, got)
}

func TestOrder_BaselineEvolutionRequirementDiffs(t *testing.T) {
	ids, want := orderVectors(t)
	baseline := func(title string) hdf.HDFBaseline {
		reqs := make([]hdf.BaselineRequirement, 0, len(ids))
		for _, id := range ids {
			reqs = append(reqs, makeBaselineReq(id, title, 0.5, []hdf.Description{}, map[string]any{}))
		}
		return makeHdfBaseline("order-stig", "1.0", reqs...)
	}
	comp, err := DiffBaselines(baseline("Old"), baseline("New"), Options{})
	require.NoError(t, err)
	assert.Equal(t, want, diffIDs(comp.RequirementDiffs))
}

func TestOrder_SystemComponentDiffs(t *testing.T) {
	ids, want := orderVectors(t)
	comps := make([]any, 0, len(ids))
	for _, name := range ids {
		comps = append(comps, map[string]any{"name": name, "type": "application"})
	}
	comp, err := DiffSystems(context.Background(),
		map[string]any{"name": "Order-Prod", "components": []any{}},
		map[string]any{"name": "Order-Prod", "components": comps})
	require.NoError(t, err)
	got := make([]string, 0, len(comp.ComponentDiffs))
	for _, d := range comp.ComponentDiffs {
		got = append(got, d.Name)
	}
	assert.Equal(t, want, got)
}

func TestOrder_SBOMPackageDiffs(t *testing.T) {
	ids, want := orderVectors(t)
	bom := func(names []string) []byte {
		comps := make([]any, 0, len(names))
		for _, name := range names {
			comps = append(comps, map[string]any{"type": "library", "name": name, "version": "1.0.0"})
		}
		raw, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": comps})
		require.NoError(t, err)
		return raw
	}
	result, err := DiffSBOMs(bom(nil), bom(ids))
	require.NoError(t, err)
	got := make([]string, 0, len(result.PackageDiffs))
	for _, d := range result.PackageDiffs {
		got = append(got, d.Name)
	}
	assert.Equal(t, want, got)
}

func TestOrder_EventKeysAndSameSequenceEventIDs(t *testing.T) {
	ids, want := orderVectors(t)
	var byRequirement, oneChain []*hdf.HDFRequirementChangeEvent
	for _, id := range ids {
		byRequirement = append(byRequirement, &hdf.HDFRequirementChangeEvent{RequirementID: id, Sequence: 1, EventID: "e"})
		oneChain = append(oneChain, &hdf.HDFRequirementChangeEvent{RequirementID: "SV-1", Sequence: 1, EventID: id})
	}
	_, keys := groupEventChains(byRequirement)
	assert.Equal(t, want, keys)

	chains, _ := groupEventChains(oneChain)
	got := make([]string, 0, len(ids))
	for _, ev := range chains["SV-1"] {
		got = append(got, ev.EventID)
	}
	assert.Equal(t, want, got)
}

func TestOrder_FoldRequirementDiffs(t *testing.T) {
	ids, want := orderVectors(t)
	seed := orderResultsJSON(t, "passed", ids)
	events := aeDeriveStream(t, seed, orderResultsJSON(t, "failed", reversed(ids)))
	result, err := FoldChangeEventsIntoComparison(seed, events)
	require.NoError(t, err)
	assert.Equal(t, want, diffIDs(result.Comparison.RequirementDiffs))
}

func TestOrder_ApplySameSequenceInsertions(t *testing.T) {
	ids, want := orderVectors(t)
	seed := orderResultsJSON(t, "passed", nil)
	events := aeDeriveStream(t, seed, orderResultsJSON(t, "failed", ids))
	for _, ev := range events {
		ev.Sequence = 1
	}
	result, err := ApplyChangeEvents(seed, events, aeInputs())
	require.NoError(t, err)
	var doc struct {
		Baselines []struct {
			Requirements []struct {
				ID string `json:"id"`
			} `json:"requirements"`
		} `json:"baselines"`
	}
	require.NoError(t, json.Unmarshal(result.Results, &doc))
	require.Len(t, doc.Baselines, 1)
	got := make([]string, 0, len(ids))
	for _, r := range doc.Baselines[0].Requirements {
		got = append(got, r.ID)
	}
	assert.Equal(t, want, got)
}
