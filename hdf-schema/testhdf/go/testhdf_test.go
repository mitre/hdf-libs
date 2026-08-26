package testhdf

import (
	"encoding/json"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validate(t *testing.T, doc hdf.HDFResults) {
	t.Helper()
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	res := validators.ValidateResults(data)
	require.True(t, res.Valid, "builder output must be schema-valid hdf-results:\n%s", res.Error())
}

func TestResults_DefaultsAreSchemaValid(t *testing.T) {
	validate(t, Results(Req("X")))
}

func TestResults_WithOptionsIsSchemaValid(t *testing.T) {
	validate(t, Results(
		Req("AC-1", Severity("high"), Impact(0.7), Status(hdf.Failed), Tag("nist", []string{"AC-1"}), CWE("CWE-79")),
		Req("AC-2", Status(hdf.Passed), AddDesc("check", "the check text")),
	))
}

func TestReq_Defaults(t *testing.T) {
	r := Req("X")
	assert.Equal(t, "X", r.ID)
	assert.Equal(t, 0.0, r.Impact)
	require.Len(t, r.Descriptions, 1)
	assert.Equal(t, "default", r.Descriptions[0].Label)
	require.Len(t, r.Results, 1)
	assert.Equal(t, hdf.NotReviewed, r.Results[0].Status)
	assert.Equal(t, DefaultStartTime, r.Results[0].StartTime)
}

func TestReq_OptionsApply(t *testing.T) {
	r := Req("X", Severity("critical"), Impact(1.0), Status(hdf.Failed))
	require.NotNil(t, r.Severity)
	assert.Equal(t, hdf.Severity("critical"), *r.Severity)
	assert.Equal(t, 1.0, r.Impact)
	assert.Equal(t, hdf.Failed, r.Results[0].Status)
}

func TestDoc_MultiBaseline(t *testing.T) {
	doc := Doc(Baseline("b1", Req("X")), Baseline("b2", Req("Y")))
	require.Len(t, doc.Baselines, 2)
	assert.Equal(t, "b1", doc.Baselines[0].Name)
	assert.Equal(t, "b2", doc.Baselines[1].Name)
	validate(t, doc)
}
