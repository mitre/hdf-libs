package asff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func fixtureDir() string {
	return filepath.Join(shared.GetConvertersDir(), "asff-to-hdf", "fixtures", "input")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir(), name))
	require.NoError(t, err)
	return data
}

// baselineByName finds a baseline by its Name, failing the test if absent.
func baselineByName(t *testing.T, r *hdf.HDFResults, name string) hdf.EvaluatedBaseline {
	t.Helper()
	for _, b := range r.Baselines {
		if b.Name == name {
			return b
		}
	}
	names := make([]string, 0, len(r.Baselines))
	for _, b := range r.Baselines {
		names = append(names, b.Name)
	}
	require.Failf(t, "baseline not found", "want %q, have %v", name, names)
	return hdf.EvaluatedBaseline{}
}

func requirementIDs(b hdf.EvaluatedBaseline) []string {
	ids := make([]string, 0, len(b.Requirements))
	for _, req := range b.Requirements {
		ids = append(ids, req.ID)
	}
	return ids
}

func TestConvertAsff_Minimal_SplitsBaselinesPerStandard(t *testing.T) {
	result, err := ConvertAsffToHDF(loadFixture(t, "minimal.json"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "asff-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
	require.NotNil(t, result.Timestamp)

	// One baseline per Security Hub standard.
	require.Len(t, result.Baselines, 2)

	cis := baselineByName(t, result, "CIS AWS Foundations Benchmark v1.2.0")
	assert.ElementsMatch(t, []string{"1.1", "2.5"}, requirementIDs(cis))

	afsbp := baselineByName(t, result, "AWS Foundational Security Best Practices v1.0.0")
	assert.ElementsMatch(t, []string{"S3.2", "Config.1"}, requirementIDs(afsbp))
}

func TestConvertAsff_Minimal_StatusAndImpact(t *testing.T) {
	result, err := ConvertAsffToHDF(loadFixture(t, "minimal.json"), converterVersion)
	require.NoError(t, err)

	afsbp := baselineByName(t, result, "AWS Foundational Security Best Practices v1.0.0")

	var s32, config1 hdf.EvaluatedRequirement
	for _, req := range afsbp.Requirements {
		switch req.ID {
		case "S3.2":
			s32 = req
		case "Config.1":
			config1 = req
		}
	}

	// S3.2 is PASSED in the fixture; INFORMATIONAL severity is up-graded to MEDIUM (0.5) for Security Hub.
	require.Len(t, s32.Results, 1)
	assert.Equal(t, hdf.Passed, s32.Results[0].Status)
	assert.InDelta(t, 0.5, s32.Impact, 0.0001)

	// Config.1 is FAILED, MEDIUM.
	require.Len(t, config1.Results, 1)
	assert.Equal(t, hdf.Failed, config1.Results[0].Status)
	assert.InDelta(t, 0.5, config1.Impact, 0.0001)

	// Every result carries a non-empty codeDesc (resource summary) and a start time.
	for _, req := range afsbp.Requirements {
		for _, res := range req.Results {
			assert.NotEmpty(t, res.CodeDesc)
			assert.False(t, res.StartTime.IsZero())
		}
	}
}

func TestConvertAsff_Minimal_CloudAccountComponent(t *testing.T) {
	result, err := ConvertAsffToHDF(loadFixture(t, "minimal.json"), converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	assert.Equal(t, "123456789123", result.Components[0].Name)
	assert.Equal(t, hdf.CloudAccount, result.Components[0].Type)
}

func TestConvertAsff_SecurityHubSample_IsSchemaValid(t *testing.T) {
	result, err := ConvertAsffToHDF(loadFixture(t, "securityhub_sample.json"), converterVersion)
	require.NoError(t, err)

	// 18 real findings across two standards → two baselines.
	require.Len(t, result.Baselines, 2)

	out, err := json.Marshal(result)
	require.NoError(t, err)
	v := validators.ValidateResults(out)
	assert.Truef(t, v.Valid, "converter output must pass HDF schema validation: %s", v.Error())
}

func TestConvertAsff_EmptyFindings_SynthesizesPassedPlaceholder(t *testing.T) {
	result, err := ConvertAsffToHDF(loadFixture(t, "empty.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "asff-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)

	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.True(t, validators.ValidateResults(out).Valid)
}

func TestConvertAsff_InvalidInput(t *testing.T) {
	_, err := ConvertAsffToHDF([]byte("not valid json"), converterVersion)
	assert.Error(t, err)
}

func TestConvertAsff_EmptyInput(t *testing.T) {
	_, err := ConvertAsffToHDF([]byte(""), converterVersion)
	assert.Error(t, err)
}

// --- helper-level unit tests: cover the branches the real fixtures don't ---

func TestMapComplianceStatus(t *testing.T) {
	cases := map[string]hdf.ResultStatus{
		"PASSED":        hdf.Passed,
		"FAILED":        hdf.Failed,
		"WARNING":       hdf.NotReviewed,
		"NOT_AVAILABLE": hdf.NotReviewed,
		"":              hdf.Failed, // absent Compliance.Status defaults to failed
		"BOGUS":         hdf.Error,
	}
	for input, want := range cases {
		assert.Equalf(t, want, mapComplianceStatus(input), "status %q", input)
	}
}

func TestSeverityLabelToImpact(t *testing.T) {
	cases := map[string]float64{
		"CRITICAL":      0.9,
		"HIGH":          0.7,
		"MEDIUM":        0.5,
		"LOW":           0.3,
		"INFORMATIONAL": 0.0,
	}
	for label, want := range cases {
		assert.InDeltaf(t, want, severityLabelToImpact(label), 0.0001, "label %q", label)
	}
}

func TestSuppressedWorkflowForcesZeroImpact(t *testing.T) {
	f := asffFinding{
		Severity: asffSeverity{Label: "CRITICAL"},
		Workflow: asffWorkflow{Status: "SUPPRESSED"},
	}
	assert.InDelta(t, 0.0, findingImpact(f, nil), 0.0001)
}

// --- branch coverage for helpers and non-Security-Hub / default paths ---

func TestParseFindings_Shapes(t *testing.T) {
	fs, err := parseFindings([]byte(`{"Findings":[{"Id":"c"}]}`))
	require.NoError(t, err)
	require.Len(t, fs, 1)

	fs, err = parseFindings([]byte(`[{"Id":"a","ProductArn":"arn:aws:securityhub:us-east-1::product/aws/guardduty"}]`))
	require.NoError(t, err)
	require.Len(t, fs, 1)

	fs, err = parseFindings([]byte(`{"Id":"b","ProductArn":"x"}`))
	require.NoError(t, err)
	require.Len(t, fs, 1)

	_, err = parseFindings([]byte(`nope`))
	assert.Error(t, err)
}

func TestBaselineName_NonSecurityHubAndEmpty(t *testing.T) {
	gd := asffFinding{ProductArn: "arn:aws:securityhub:us-east-1::product/aws/guardduty"}
	assert.Equal(t, "aws - guardduty", baselineName(gd))
	assert.Equal(t, "AWS Security Finding Format", baselineName(asffFinding{}))
}

func TestControlID_Fallbacks(t *testing.T) {
	gd := asffFinding{ProductArn: "arn:aws:securityhub:us-east-1::product/aws/guardduty", GeneratorID: "foo/bar/GD.1"}
	assert.Equal(t, "GD.1", controlID(gd))
	assert.Equal(t, "theid", controlID(asffFinding{ID: "theid"}))
}

func TestImpact_Fallbacks(t *testing.T) {
	assert.InDelta(t, 0.0, severityLabelToImpact("WHATEVER"), 0.0001)

	n := 40.0
	gd := asffFinding{ProductArn: "arn:aws:securityhub:us-east-1::product/aws/guardduty", Severity: asffSeverity{Normalized: &n}}
	assert.InDelta(t, 0.4, findingImpact(gd, nil), 0.0001)

	assert.InDelta(t, 0.9, findingImpact(asffFinding{}, &standardsControl{SeverityRating: "CRITICAL"}), 0.0001)
}

func TestSecurityHubStandardName_TitleCaseElseBranch(t *testing.T) {
	// No Types → title-case the ARN slug.
	f := asffFinding{ProductFields: map[string]string{
		"StandardsControlArn": "arn:aws:securityhub:us-east-1:1:control/pci-dss/v/3.2.1/PCI.S3.1",
	}}
	assert.Equal(t, "Pci Dss v3.2.1", securityHubStandardName(f))
}

func TestRemediationResourceAndStatusHelpers(t *testing.T) {
	var f asffFinding
	f.Remediation.Recommendation.Text = "do X"
	f.Remediation.Recommendation.URL = "http://u"
	assert.Equal(t, "do X\nhttp://u", remediationText(f))

	f2 := asffFinding{Resources: []asffResource{{Type: "AwsAccount", ID: "acct", Partition: "aws", Region: "us-east-1"}}}
	assert.Equal(t, "Resources: [Type: AwsAccount, Id: acct, Partition: aws, Region: us-east-1]", resourceCodeDesc(f2))

	f3 := asffFinding{Compliance: asffCompliance{StatusReasons: []asffStatusReason{{ReasonCode: "RC", Description: "desc"}}}}
	assert.Equal(t, "ReasonCode: RC\nDescription: desc", statusReason(f3))
}

func TestBuildRequirement_RefsAndNormalizedImpact(t *testing.T) {
	n := 70.0
	f := asffFinding{
		ID:          "x",
		ProductArn:  "arn:aws:securityhub:us-east-1::product/aws/guardduty",
		Title:       "T",
		Description: "D",
		SourceURL:   "http://ref",
		Severity:    asffSeverity{Normalized: &n},
		Compliance:  asffCompliance{Status: "FAILED"},
	}
	req := buildRequirement("x", []asffFinding{f})
	assert.InDelta(t, 0.7, req.Impact, 0.0001)
	require.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "http://ref", *req.Refs[0].URL)
}

// --- product special-cases: Prowler, Trivy ---

func TestConvertAsff_Prowler(t *testing.T) {
	result, err := ConvertAsffToHDF(loadFixture(t, "prowler_sample.json"), converterVersion)
	require.NoError(t, err)

	// Prowler → one baseline named by ProviderName.
	require.Len(t, result.Baselines, 1)
	b := result.Baselines[0]
	assert.Equal(t, "Prowler", b.Name)
	// control ids are GeneratorId after the first hyphen (prowler-check11 → check11).
	assert.ElementsMatch(t, []string{"check11", "check12"}, requirementIDs(b))

	for _, req := range b.Requirements {
		// Prowler folds its description into the result codeDesc; control desc is blank.
		require.NotEmpty(t, req.Descriptions)
		assert.Equal(t, " ", req.Descriptions[0].Data)
		for _, res := range req.Results {
			assert.Equal(t, hdf.Failed, res.Status)
			assert.NotEmpty(t, res.CodeDesc)
		}
	}

	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.Truef(t, validators.ValidateResults(out).Valid, "%s", validators.ValidateResults(out).Error())
}

func TestConvertAsff_Prowler_NDJSON(t *testing.T) {
	jsonResult, err := ConvertAsffToHDF(loadFixture(t, "prowler_sample.json"), converterVersion)
	require.NoError(t, err)
	ndjsonResult, err := ConvertAsffToHDF(loadFixture(t, "prowler_sample.ndjson"), converterVersion)
	require.NoError(t, err)

	// NDJSON and JSON forms of the same Prowler data yield the same baseline + control set.
	require.Len(t, ndjsonResult.Baselines, 1)
	assert.Equal(t, "Prowler", ndjsonResult.Baselines[0].Name)
	assert.ElementsMatch(t, requirementIDs(jsonResult.Baselines[0]), requirementIDs(ndjsonResult.Baselines[0]))
}

func TestConvertAsff_Trivy(t *testing.T) {
	result, err := ConvertAsffToHDF(loadFixture(t, "trivy_sample.json"), converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	b := result.Baselines[0]
	assert.Equal(t, "Aqua Security - Trivy", b.Name)

	var cve hdf.EvaluatedRequirement
	for _, req := range b.Requirements {
		if req.ID == "Trivy/CVE-2021-36159" {
			cve = req
		}
	}
	require.Equal(t, "Trivy/CVE-2021-36159", cve.ID)
	require.Len(t, cve.Results, 1)
	assert.Equal(t, hdf.Failed, cve.Results[0].Status)
	require.NotNil(t, cve.Results[0].Message)
	assert.Contains(t, *cve.Results[0].Message, "For package apk-tools")
	// CVE findings map to the remediation NIST bundle.
	assert.ElementsMatch(t, []interface{}{"SI-2", "RA-5"}, cve.Tags["nist"])

	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.Truef(t, validators.ValidateResults(out).Valid, "%s", validators.ValidateResults(out).Error())
}
