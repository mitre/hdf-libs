package cklb

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "1.0.0"

func fixtureDir() string {
	return filepath.Join(shared.GetConvertersDir(), "cklb-to-hdf", "fixtures", "input")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir(), name))
	require.NoError(t, err)
	return data
}

// findReq returns the requirement with the given ID, or fails the test.
func findReq(t *testing.T, reqs []hdf.EvaluatedRequirement, id string) hdf.EvaluatedRequirement {
	t.Helper()
	for _, r := range reqs {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("requirement %s not found", id)
	return hdf.EvaluatedRequirement{}
}

func TestConvertCKLBToHDF_Structure(t *testing.T) {
	result, err := ConvertCKLBToHDF(loadFixture(t, "firefox-stig.cklb"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "cklb-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "DISA STIG Viewer", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "CKLB", *result.Tool.Format)
	require.NotNil(t, result.Timestamp)

	require.Len(t, result.Baselines, 1)
	bl := result.Baselines[0]
	assert.Equal(t, "STIG Checklist Scan", bl.Name)
	require.NotNil(t, bl.Title)
	assert.Equal(t, "Mozilla Firefox Security Technical Implementation Guide", *bl.Title)
	assert.Len(t, bl.Requirements, 6)
}

func TestConvertCKLBToHDF_Component(t *testing.T) {
	result, err := ConvertCKLBToHDF(loadFixture(t, "firefox-stig.cklb"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Components, 1)

	c := result.Components[0]
	assert.Equal(t, "EXAMPLE-HOST", c.Name)
	assert.Equal(t, hdf.Host, c.Type)
	require.NotNil(t, c.IPAddress)
	assert.Equal(t, "192.0.2.10", *c.IPAddress)
	require.NotNil(t, c.FQDN)
	assert.Equal(t, "host.example.com", *c.FQDN)
	require.NotNil(t, c.MACAddress)
	assert.Equal(t, "00:00:00:00:00:00", *c.MACAddress)
}

func TestConvertCKLBToHDF_StatusMapping(t *testing.T) {
	result, err := ConvertCKLBToHDF(loadFixture(t, "firefox-stig.cklb"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// open -> Failed
	assert.Equal(t, hdf.Failed, findReq(t, reqs, "V-251545").Results[0].Status)
	// not_a_finding -> Passed
	assert.Equal(t, hdf.Passed, findReq(t, reqs, "V-251546").Results[0].Status)
	// not_applicable -> NotApplicable
	assert.Equal(t, hdf.NotApplicable, findReq(t, reqs, "V-251547").Results[0].Status)
	// not_reviewed -> NotReviewed
	assert.Equal(t, hdf.NotReviewed, findReq(t, reqs, "V-251559").Results[0].Status)
}

func TestConvertCKLBToHDF_RequirementFields(t *testing.T) {
	result, err := ConvertCKLBToHDF(loadFixture(t, "firefox-stig.cklb"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	r := findReq(t, reqs, "V-251545")
	require.NotNil(t, r.Title)
	assert.Equal(t, "The installed version of Firefox must be supported.", *r.Title)
	assert.InDelta(t, 0.7, r.Impact, 0.001) // high

	// NIST tag derived from CCI-002605 -> SI-2 c
	nist, ok := r.Tags["nist"].([]string)
	require.True(t, ok, "nist tag should be []string")
	assert.Contains(t, nist, "SI-2 c")
	cciTag, ok := r.Tags["cci"].([]string)
	require.True(t, ok)
	assert.Contains(t, cciTag, "CCI-002605")

	// controlType derived from NIST family (SI -> technical); verificationMethod omitted
	require.NotNil(t, r.ControlType, "controlType should be derived from NIST tag")
	assert.Equal(t, hdf.Technical, *r.ControlType)
	assert.Nil(t, r.VerificationMethod, "verificationMethod must be omitted for CKLB")
	assert.Nil(t, r.Applicability, "applicability must be omitted for CKLB")
}

func TestConvertCKLBToHDF_ImpactFromSeverityRegardlessOfStatus(t *testing.T) {
	result, err := ConvertCKLBToHDF(loadFixture(t, "firefox-stig.cklb"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// V-251547 is medium severity + not_applicable status; impact tracks
	// severity (0.5), status carries the applicability.
	r := findReq(t, reqs, "V-251547")
	assert.InDelta(t, 0.5, r.Impact, 0.001)
	assert.Equal(t, hdf.NotApplicable, r.Results[0].Status)

	// V-251559 is low severity
	assert.InDelta(t, 0.3, findReq(t, reqs, "V-251559").Impact, 0.001)
}

func TestConvertCKLBToHDF_NoVerificationMethodAnywhere(t *testing.T) {
	result, err := ConvertCKLBToHDF(loadFixture(t, "firefox-stig.cklb"), converterVersion)
	require.NoError(t, err)
	for _, r := range result.Baselines[0].Requirements {
		assert.Nilf(t, r.VerificationMethod,
			"verificationMethod must be omitted for every CKLB requirement (%s)", r.ID)
	}
}

func TestConvertCKLBToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertCKLBToHDF([]byte(""), converterVersion)
	assert.Error(t, err)
}

func TestConvertCKLBToHDF_InvalidInput(t *testing.T) {
	_, err := ConvertCKLBToHDF([]byte("not valid json at all"), converterVersion)
	assert.Error(t, err)
}

func TestConvertCKLBToHDF_OversizedInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	_, err := ConvertCKLBToHDF(big, converterVersion)
	assert.Error(t, err)
}

// Pins safe behavior: an all-passing CKLB must emit one requirement per rule, never requirements:[].
func TestConvertCKLBToHDF_AllPassingNotEmpty(t *testing.T) {
	input := loadFixture(t, "all-passing.cklb")
	result, err := ConvertCKLBToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	reqs := result.Baselines[0].Requirements
	// Ground-truth anchor: one requirement per stigs[].rules[] entry.
	shared.AssertRequirementCount(t, result, shared.CountJSONItemsUnderKey(t, input, "rules"),
		"all-passing.cklb: one requirement per stigs[].rules[]")

	for _, r := range reqs {
		require.Len(t, r.Results, 1)
		assert.Equal(t, hdf.Passed, r.Results[0].Status)
	}
}

// Ground-truth anchor over the firefox fixture: one requirement per
// stigs[].rules[], counted independently of the converter (shared/go/anchor.go).
func TestConvertCKLBToHDF_RulesAnchor(t *testing.T) {
	input := loadFixture(t, "firefox-stig.cklb")
	result, err := ConvertCKLBToHDF(input, converterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, shared.CountJSONItemsUnderKey(t, input, "rules"),
		"firefox-stig.cklb: one requirement per stigs[].rules[]")
}

func TestSnapshots(t *testing.T) {
	// STIG checklist (.cklb) carries no scan time.
	shared.RunSnapshotTests(t, "cklb-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertCKLBToHDF(input, converterVersion)
	}, "*")
}

// Status, parsing, and field-mapping helpers are unit-tested in the shared
// checklist package (shared/go/checklist); these converter tests exercise the
// public ConvertCKLBToHDF entry point against the committed fixture.

// finding_details and comments are separate fields in CKLB; message carries
// finding_details alone and comments round-trips through a tag.
func TestConvertCKLBToHDF_CommentsStaySeparateFromFindingDetails(t *testing.T) {
	result, err := ConvertCKLBToHDF(loadFixture(t, "firefox-stig.cklb"), converterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.NotEmpty(t, req.Results)
	require.NotNil(t, req.Results[0].Message)

	assert.Equal(t, "Installed Firefox version is end-of-life and unsupported.", *req.Results[0].Message)
	assert.NotContains(t, *req.Results[0].Message, "Synthetic checklist")
	assert.Equal(t, "Synthetic checklist for hdf-libs converter test fixture - not a real assessment.", req.Tags["comments"])
}
