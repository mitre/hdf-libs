package ckl

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
	return filepath.Join(shared.GetConvertersDir(), "ckl-to-hdf", "fixtures", "input")
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

func TestConvertCKLToHDF_Structure(t *testing.T) {
	result, err := ConvertCKLToHDF(loadFixture(t, "firefox-stig.ckl"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "hdf-converters", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "DISA STIG Viewer", *result.Tool.Name)
	require.NotNil(t, result.Timestamp)

	require.Len(t, result.Baselines, 1)
	bl := result.Baselines[0]
	assert.Equal(t, "STIG Checklist Scan", bl.Name)
	require.NotNil(t, bl.Title)
	assert.Equal(t, "Mozilla Firefox Security Technical Implementation Guide", *bl.Title)
	assert.Len(t, bl.Requirements, 6)
}

func TestConvertCKLToHDF_Component(t *testing.T) {
	result, err := ConvertCKLToHDF(loadFixture(t, "firefox-stig.ckl"), converterVersion)
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

func TestConvertCKLToHDF_StatusMapping(t *testing.T) {
	result, err := ConvertCKLToHDF(loadFixture(t, "firefox-stig.ckl"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// Open -> Failed
	assert.Equal(t, hdf.Failed, findReq(t, reqs, "V-251545").Results[0].Status)
	// NotAFinding -> Passed
	assert.Equal(t, hdf.Passed, findReq(t, reqs, "V-251546").Results[0].Status)
	// Not_Applicable -> NotApplicable
	assert.Equal(t, hdf.NotApplicable, findReq(t, reqs, "V-251547").Results[0].Status)
	// Not_Reviewed -> NotReviewed
	assert.Equal(t, hdf.NotReviewed, findReq(t, reqs, "V-251559").Results[0].Status)
}

func TestConvertCKLToHDF_RequirementFields(t *testing.T) {
	result, err := ConvertCKLToHDF(loadFixture(t, "firefox-stig.ckl"), converterVersion)
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
	assert.Nil(t, r.VerificationMethod, "verificationMethod must be omitted for CKL")
	assert.Nil(t, r.Applicability, "applicability must be omitted for CKL")

	// Finding details surfaced in the result message
	require.NotNil(t, r.Results[0].Message)
	assert.Contains(t, *r.Results[0].Message, "end-of-life")
}

func TestConvertCKLToHDF_ImpactFromSeverityRegardlessOfStatus(t *testing.T) {
	result, err := ConvertCKLToHDF(loadFixture(t, "firefox-stig.ckl"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// V-251547 is medium severity + Not_Applicable status; impact tracks
	// severity (0.5), status carries the applicability (matches xccdf convention).
	r := findReq(t, reqs, "V-251547")
	assert.InDelta(t, 0.5, r.Impact, 0.001)
	assert.Equal(t, hdf.NotApplicable, r.Results[0].Status)

	// V-251559 is low severity
	assert.InDelta(t, 0.3, findReq(t, reqs, "V-251559").Impact, 0.001)
}

func TestConvertCKLToHDF_NoVerificationMethodAnywhere(t *testing.T) {
	result, err := ConvertCKLToHDF(loadFixture(t, "firefox-stig.ckl"), converterVersion)
	require.NoError(t, err)
	for _, r := range result.Baselines[0].Requirements {
		assert.Nilf(t, r.VerificationMethod,
			"verificationMethod must be omitted for every CKL requirement (%s)", r.ID)
	}
}

func TestConvertCKLToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertCKLToHDF([]byte(""), converterVersion)
	assert.Error(t, err)
}

func TestConvertCKLToHDF_InvalidInput(t *testing.T) {
	_, err := ConvertCKLToHDF([]byte("not valid xml at all"), converterVersion)
	assert.Error(t, err)
}

func TestConvertCKLToHDF_WrongRootElement(t *testing.T) {
	_, err := ConvertCKLToHDF([]byte("<?xml version=\"1.0\"?><Benchmark></Benchmark>"), converterVersion)
	assert.Error(t, err)
}

// minimalCKL is a hand-built CKL with no ASSET host and a VULN with no CCI,
// exercising the "omit component" and "empty nist" branches.
const minimalCKL = `<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET>
    <HOST_NAME></HOST_NAME>
    <HOST_IP></HOST_IP>
    <HOST_FQDN></HOST_FQDN>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Bare STIG</SID_DATA></SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>low</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Bare rule</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>Open</STATUS>
        <FINDING_DETAILS></FINDING_DETAILS>
        <COMMENTS></COMMENTS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>`

func TestConvertCKLToHDF_NoHostNoCCI(t *testing.T) {
	result, err := ConvertCKLToHDF([]byte(minimalCKL), converterVersion)
	require.NoError(t, err)

	// No identifiable host -> Components omitted entirely.
	assert.Empty(t, result.Components)

	r := result.Baselines[0].Requirements[0]
	// No CCI -> empty nist slice, no controlType derived, no message.
	nist, ok := r.Tags["nist"].([]string)
	require.True(t, ok)
	assert.Empty(t, nist)
	assert.Nil(t, r.ControlType)
	assert.Nil(t, r.VerificationMethod)
	assert.Nil(t, r.Results[0].Message)
}

func TestConvertCKLToHDF_OversizedInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	_, err := ConvertCKLToHDF(big, converterVersion)
	assert.Error(t, err)
}

// Pins safe behavior: an all-passing CKL must produce one requirement per VULN
// (never an empty requirements slice) so a future refactor cannot silently
// introduce the "emit empty requirements" anti-pattern.
func TestConvertCKLToHDF_AllPassingProducesRequirements(t *testing.T) {
	result, err := ConvertCKLToHDF(loadFixture(t, "all-passing.ckl"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 3, "all-passing.ckl has 3 VULN entries; converter must emit 3 requirements")
	for _, r := range reqs {
		require.NotEmpty(t, r.Results, "requirement %s must have at least one result", r.ID)
		assert.Equal(t, hdf.Passed, r.Results[0].Status, "requirement %s status should be passed (NotAFinding)", r.ID)
	}
}

// Status, parsing, and field-mapping helpers are unit-tested in the shared
// checklist package (shared/go/checklist); these converter tests exercise the
// public ConvertCKLToHDF entry point against the committed fixture.
