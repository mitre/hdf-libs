package hdfengine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The count helpers are pinned by the same table test/status-counts-rollup.test.ts
// reads, so the Go and TypeScript roll-ups cannot drift. The table is written in
// the TypeScript field spelling; severityTable/countsTable below are the only
// place that spelling is translated, because StatusCounts' own json tags are the
// wire shape the MCP serializes and must not be bent to suit a fixture.
type severityTable struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
	Total         int `json:"total"`
}

func (s severityTable) counts() SeverityCounts {
	return SeverityCounts(s)
}

type countsTable struct {
	Passed   severityTable `json:"passed"`
	Failed   severityTable `json:"failed"`
	Skipped  severityTable `json:"skipped"`
	Error    severityTable `json:"error"`
	NoImpact severityTable `json:"noImpact"`
}

func (c countsTable) counts() *StatusCounts {
	return &StatusCounts{
		Passed:   c.Passed.counts(),
		Failed:   c.Failed.counts(),
		Skipped:  c.Skipped.counts(),
		Error:    c.Error.counts(),
		NoImpact: c.NoImpact.counts(),
	}
}

type rollupCase struct {
	Name               string        `json:"name"`
	Note               string        `json:"note"`
	Inputs             []countsTable `json:"inputs"`
	Want               countsTable   `json:"want"`
	WantSeverityTotals severityTable `json:"wantSeverityTotals"`
}

func loadRollupCases(t *testing.T) []rollupCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "status-counts-rollup-cases.json"))
	require.NoError(t, err)
	var table struct {
		Cases []rollupCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases)
	return table.Cases
}

func TestAddCounts(t *testing.T) {
	for _, c := range loadRollupCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			inputs := make([]*StatusCounts, len(c.Inputs))
			for i, in := range c.Inputs {
				inputs[i] = in.counts()
			}
			assert.Equal(t, c.Want.counts(), AddCounts(inputs...), c.Note)
		})
	}
}

func TestSeverityTotals(t *testing.T) {
	for _, c := range loadRollupCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			assert.Equal(t, c.WantSeverityTotals.counts(), SeverityTotals(c.Want.counts()), c.Note)
		})
	}
}

// A sum that rewrote its arguments would corrupt the per-source and per-baseline
// rows the HTML report prints alongside the whole, which are the same objects it
// sums.
func TestAddCountsDoesNotMutateItsArguments(t *testing.T) {
	for _, c := range loadRollupCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			inputs := make([]*StatusCounts, len(c.Inputs))
			for i, in := range c.Inputs {
				inputs[i] = in.counts()
			}
			AddCounts(inputs...)
			for i, in := range c.Inputs {
				assert.Equal(t, in.counts(), inputs[i], "input %d must be unchanged", i)
			}
		})
	}
}

func TestSeverityTotalsDoesNotMutateItsArgument(t *testing.T) {
	counts := countsTable{Passed: severityTable{Critical: 1, Total: 1}}.counts()
	SeverityTotals(counts)
	assert.Equal(t, countsTable{Passed: severityTable{Critical: 1, Total: 1}}.counts(), counts)
}

// Both helpers are exported and take pointers, so a caller can reach them with a
// nil it did not mean to pass; an empty count set is the honest answer and a
// panic inside a library is not.
func TestCountHelpersTolerateNil(t *testing.T) {
	assert.Equal(t, &StatusCounts{}, AddCounts())
	assert.Equal(t, &StatusCounts{}, AddCounts(nil, nil))
	assert.Equal(t, SeverityCounts{}, SeverityTotals(nil))

	one := countsTable{Failed: severityTable{High: 2, Total: 2}}.counts()
	assert.Equal(t, one, AddCounts(nil, one, nil), "a nil is skipped, not a zeroing")
}
