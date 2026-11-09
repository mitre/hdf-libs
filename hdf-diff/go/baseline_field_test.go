package diff

import (
	"context"
	"encoding/json"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every requirement diff names its baseline, `(multiple)` when the id sits in
// more than one, and the document stays schema-valid with the field present.
func TestRequirementDiff_CarriesBaselineAndValidates(t *testing.T) {
	shared := makeRequirement("SV-001", hdf.Failed, 0.7)
	only := makeRequirement("SV-002", hdf.Passed, 0.5)
	old := makeResults(
		makeBaseline("alpha", version100, shared, only),
		makeBaseline("beta", version100, shared),
	)
	updated := makeResults(
		makeBaseline("alpha", version100, makeRequirement("SV-001", hdf.Passed, 0.7), only),
		makeBaseline("beta", version100, makeRequirement("SV-001", hdf.Passed, 0.7)),
	)

	comp := mustDiffHdf(t, old, []hdf.HDFResults{updated}, defaultOpts())

	byID := map[string]string{}
	for _, rd := range comp.RequirementDiffs {
		byID[rd.ID] = rd.Baseline
	}
	assert.Equal(t, baselineMultiple, byID["SV-001"], "an id in two baselines reports the sentinel")
	assert.Equal(t, "alpha", byID["SV-002"], "an id in one baseline reports that baseline")

	raw, err := json.Marshal(comp)
	require.NoError(t, err)
	validation := validators.ValidateComparison(raw)
	assert.True(t, validation.Valid, "a comparison carrying baseline must be schema-valid: %v", validation.Errors)
}

// The same fixture pair and the same assertion as hdf-diff/test/diff.test.ts,
// so the two engines are shown to agree on the field rather than assumed to.
func TestRequirementDiff_BaselineParityOnSharedFixtures(t *testing.T) {
	var before, after hdf.HDFResults
	require.NoError(t, json.Unmarshal(aeLoadFixture(t, "scan-before.json"), &before))
	require.NoError(t, json.Unmarshal(aeLoadFixture(t, "scan-after.json"), &after))

	comp, err := DiffHdf(context.Background(), before, []hdf.HDFResults{after}, Options{})
	require.NoError(t, err)
	require.NotEmpty(t, comp.RequirementDiffs)
	for _, rd := range comp.RequirementDiffs {
		assert.Equal(t, "rhel9-stig-baseline", rd.Baseline, rd.ID)
	}
}
