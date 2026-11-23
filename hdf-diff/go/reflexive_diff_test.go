package diff

import (
	"context"
	"encoding/json"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A comparison is reflexive: a document compared with an identical copy reports no
// change.
// It was not, wherever an id sat in more than one baseline, because the baselines were
// pooled before matching. Peer: test/reflexive-diff.test.ts.
func TestDiffHdf_IsReflexiveOnEverySharedResultsFixture(t *testing.T) {
	cases := []struct {
		name string
		doc  []byte
		why  string
	}{
		{"inspec-multilayered", fixtures.Results.InspecMultilayered,
			"5 baselines, 533 ids carried by three of them: every entry was reported absent and new (1603 and 1603)"},
		{"duplicate-baselines", fixtures.Results.DuplicateBaselines,
			"16 baselines, all sharing one name: 53 and 53"},
		{"merge-grype", fixtures.Results.MergeGrype,
			"one baseline with genuinely repeated ids: 6 and 6"},
		{"merge-zap", fixtures.Results.MergeZap,
			"no repeated id within any baseline, but 4 baselines share ids across them: 3 and 3"},
		{"minimal", fixtures.Results.Minimal,
			"a single requirement, which was already reflexive — kept as a regression guard"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Through the CLI's ingestion normalizer: a published scan may carry a
			// zone-less timestamp, and the fixture is never rewritten.
			var doc hdf.HDFResults
			require.NoError(t, json.Unmarshal(hdfutil.NormalizeHDFTimestamps(tc.doc), &doc))

			comp, err := DiffHdf(context.Background(), doc, []hdf.HDFResults{doc}, defaultOpts())
			require.NoError(t, err)

			assert.Zero(t, comp.Summary.New, tc.why)
			assert.Zero(t, comp.Summary.Absent, tc.why)
			assert.Zero(t, comp.Summary.Fixed, tc.why)
			assert.Zero(t, comp.Summary.Regressed, tc.why)
			assert.Zero(t, comp.Summary.Updated, tc.why)
			for _, d := range comp.RequirementDiffs {
				assert.Equal(t, StateUnchanged, d.State, "%s in %q: %s", d.ID, d.Baseline, tc.why)
			}
		})
	}
}

// An id several baselines carry yields one diff per baseline, in the order the
// baselines are paired, and both languages emit that same order: ties on id are now
// routine, so the sort must be stable on both sides.
func TestDiffHdf_TiesOnIDKeepThePairingOrder(t *testing.T) {
	var doc hdf.HDFResults
	require.NoError(t, json.Unmarshal(hdfutil.NormalizeHDFTimestamps(fixtures.Results.InspecMultilayered), &doc))

	comp, err := DiffHdf(context.Background(), doc, []hdf.HDFResults{doc}, defaultOpts())
	require.NoError(t, err)

	var layers []string
	for _, d := range comp.RequirementDiffs {
		if d.ID == "SV-257777" {
			layers = append(layers, d.Baseline)
		}
	}
	assert.Equal(t, []string{
		"metawrapper", "metawrapper", "wrapper", "wrapper",
		"redhat-enterprise-linux-9-stig-baseline",
	}, layers)
}

// Two baselines of one document sharing a name are gathered as one pairing. Kept apart
// by position, the second would have nothing to pair with and its requirements would be
// reported absent and new.
func TestDiffHdf_BaselinesSharingAName(t *testing.T) {
	split := makeResults(
		makeBaseline("same", version100, makeRequirement("SV-001", hdf.ResultStatus(statusFailed), 0.7)),
		makeBaseline("same", version100, makeRequirement("SV-002", hdf.ResultStatus(statusFailed), 0.7)),
	)
	merged := makeResults(
		makeBaseline("same", version100,
			makeRequirement("SV-001", hdf.ResultStatus(statusFailed), 0.7),
			makeRequirement("SV-002", hdf.ResultStatus(statusFailed), 0.7)),
	)

	comp := mustDiffHdf(t, split, []hdf.HDFResults{merged}, defaultOpts())

	for _, d := range comp.RequirementDiffs {
		assert.Equal(t, StateUnchanged, d.State, "%s: expected the two same-named baselines to be gathered as one", d.ID)
	}
	assert.Len(t, comp.RequirementDiffs, 2)
}

// A requirement that MOVES between two baselines both present on both sides is reported
// absent and new, not unchanged: it is compared within its baseline and has no
// counterpart there. The reserved `moved` state is never emitted.
func TestDiffHdf_RequirementMovedBetweenBaselinesIsAbsentAndNew(t *testing.T) {
	before := makeResults(
		makeBaseline("alpha", version100,
			makeRequirement("SV-STAY", hdf.ResultStatus(statusFailed), 0.7),
			makeRequirement("SV-MOVER", hdf.ResultStatus(statusFailed), 0.7)),
		makeBaseline("beta", version100, makeRequirement("SV-OTHER", hdf.ResultStatus(statusFailed), 0.7)),
	)
	after := makeResults(
		makeBaseline("alpha", version100, makeRequirement("SV-STAY", hdf.ResultStatus(statusFailed), 0.7)),
		makeBaseline("beta", version100,
			makeRequirement("SV-OTHER", hdf.ResultStatus(statusFailed), 0.7),
			makeRequirement("SV-MOVER", hdf.ResultStatus(statusFailed), 0.7)),
	)

	comp := mustDiffHdf(t, before, []hdf.HDFResults{after}, defaultOpts())

	states := map[string][]RequirementState{}
	baselines := map[string][]string{}
	for _, d := range comp.RequirementDiffs {
		states[d.ID] = append(states[d.ID], d.State)
		baselines[d.ID] = append(baselines[d.ID], d.Baseline)
	}
	assert.ElementsMatch(t, []RequirementState{StateAbsent, StateNew}, states["SV-MOVER"])
	assert.ElementsMatch(t, []string{"alpha", "beta"}, baselines["SV-MOVER"])
	assert.Equal(t, []RequirementState{StateUnchanged}, states["SV-STAY"])
	assert.Equal(t, []RequirementState{StateUnchanged}, states["SV-OTHER"])
}
