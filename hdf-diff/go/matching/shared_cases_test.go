package matching

import (
	"encoding/json"
	"os"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The table read here is also read by test/matching/shared-cases.test.ts, so both engines
// are asserted against ONE definition of how a repeated id's occurrences pair up,
// ordering included, rather than two suites that can drift.

type sharedMatchCase struct {
	Name         string                     `json:"name"`
	Strategy     string                     `json:"strategy"`
	Mapping      map[string]string          `json:"mapping"`
	Old          []hdf.EvaluatedRequirement `json:"old"`
	New          []hdf.EvaluatedRequirement `json:"new"`
	Matched      [][]string                 `json:"matched"`
	UnmatchedOld []string                   `json:"unmatchedOld"`
	UnmatchedNew []string                   `json:"unmatchedNew"`
	Why          string                     `json:"why"`
}

func TestSharedDuplicateIDCases(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/duplicate-id-matching-cases.json")
	require.NoError(t, err)
	var table struct {
		Cases []sharedMatchCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)

	strategies := map[string]bool{}
	for _, tc := range table.Cases {
		strategies[tc.Strategy] = true
		t.Run(tc.Name, func(t *testing.T) {
			var strategy Strategy
			switch tc.Strategy {
			case "exactId":
				strategy = NewExactIDStrategy()
			case "mappedId":
				strategy = NewMappedIDStrategy(tc.Mapping)
			default:
				t.Fatalf("unknown strategy %q", tc.Strategy)
			}

			result := strategy.Match(tc.Old, tc.New)

			require.Len(t, result.Matched, len(tc.Matched), tc.Why)
			for i, want := range tc.Matched {
				assert.Equal(t, want[0], titleOf(result.Matched[i].OldReq), "pair %d old side: %s", i, tc.Why)
				assert.Equal(t, want[1], titleOf(result.Matched[i].NewReq), "pair %d new side: %s", i, tc.Why)
			}
			assert.Equal(t, tc.UnmatchedOld, titlesOf(result.UnmatchedOld), tc.Why)
			assert.Equal(t, tc.UnmatchedNew, titlesOf(result.UnmatchedNew), tc.Why)
		})
	}

	// A strategy added to the table without being built here would silently assert nothing.
	for _, name := range []string{"exactId", "mappedId"} {
		assert.True(t, strategies[name], "the table must carry %s cases", name)
	}
}

func titleOf(req hdf.EvaluatedRequirement) string {
	if req.Title == nil {
		return ""
	}
	return *req.Title
}

func titlesOf(reqs []hdf.EvaluatedRequirement) []string {
	titles := []string{}
	for _, req := range reqs {
		titles = append(titles, titleOf(req))
	}
	return titles
}
