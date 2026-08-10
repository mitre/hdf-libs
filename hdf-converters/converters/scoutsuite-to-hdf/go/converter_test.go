package scoutsuite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "test-version"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	fixturePath := filepath.Join("..", "fixtures", name)
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", name, err)
	}
	return data
}

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// --- Validation tests ---

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "scoutsuite-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertScoutsuiteToHDF(input, testConverterVersion) },
		MinimalFixture: "scoutsuite_sample.js",
		InvalidInput:   "not valid",
	})
}

func TestConvertScoutsuiteToHDF_PureJSON(t *testing.T) {
	// Test with JSON that has no JS variable prefix
	input := []byte(`{"account_id": "123", "provider_name": "AWS", "services": {}, "last_run": {"time": "2021-01-01 00:00:00+0000", "version": "5.0.0", "ruleset_name": "test", "ruleset_about": "test"}}`)
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	assert.Equal(t, "scoutsuite-no-findings", result.Baselines[0].Requirements[0].ID)
}

func TestConvertScoutsuiteToHDF_EmptyFindings(t *testing.T) {
	input := loadFixture(t, "input/empty.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "scoutsuite-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "ScoutSuite")
	assert.Contains(t, req.Results[0].CodeDesc, "000000000000")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

// --- Real fixture tests ---

func TestConvertScoutsuiteToHDF_BasicStructure(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines, 1)
	// 8 findings in the cloudtrail service
	assert.Len(t, result.Baselines[0].Requirements, 8)
}

func TestConvertScoutsuiteToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "scoutsuite-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)
}

func TestConvertScoutsuiteToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	assert.Equal(t, "ScoutSuite", *result.Tool.Name)
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
	assert.Equal(t, "5.10.2", *result.Tool.Version)
}

func TestConvertScoutsuiteToHDF_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "ScoutSuite Scan", result.Baselines[0].Name)
}

func TestConvertScoutsuiteToHDF_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "default")
	assert.Contains(t, *result.Baselines[0].Title, "Amazon Web Services")
	assert.Contains(t, *result.Baselines[0].Title, "916481805664")
}

func TestConvertScoutsuiteToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.Len(t, result.Baselines[0].ResultsChecksum.Value, 64)
}

func TestConvertScoutsuiteToHDF_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2021, result.Timestamp.Year())
	assert.Equal(t, 19, result.Timestamp.Day())
}

// --- Target ---

func TestConvertScoutsuiteToHDF_Target(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	assert.Contains(t, result.Components[0].Name, "916481805664")
	assert.Equal(t, hdf.CloudAccount, result.Components[0].Type)
}

// --- Impact mapping ---

func TestConvertScoutsuiteToHDF_ImpactDanger(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-not-configured has level "danger"
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")
	assert.Equal(t, 0.7, req.Impact)
}

func TestConvertScoutsuiteToHDF_ImpactWarning(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-duplicated-global-services-logging has level "warning"
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-duplicated-global-services-logging")
	assert.Equal(t, 0.5, req.Impact)
}

// --- Status mapping ---

func TestConvertScoutsuiteToHDF_StatusFailed(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-not-configured: checked_items=16, flagged_items=16 -> failed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvertScoutsuiteToHDF_StatusNotReviewed(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-duplicated-global-services-logging: checked_items=0 -> notReviewed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-duplicated-global-services-logging")
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
}

func TestGetStatus(t *testing.T) {
	assert.Equal(t, hdf.NotReviewed, getStatus(0, 0))
	assert.Equal(t, hdf.Passed, getStatus(5, 0))
	assert.Equal(t, hdf.Failed, getStatus(5, 3))
	assert.Equal(t, hdf.Failed, getStatus(16, 16))
}

// --- NIST tags ---

func TestConvertScoutsuiteToHDF_NISTMapped(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-not-configured maps to AU-12
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")

	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "nist tag missing")
	nistSlice, ok := nistVal.([]interface{})
	require.True(t, ok, "nist tag not a slice")
	assert.Contains(t, nistSlice, "AU-12")
}

func TestConvertScoutsuiteToHDF_NISTMultiControl(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-no-cloudwatch-integration maps to AU-12|SI-4(2)
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-no-cloudwatch-integration")

	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "nist tag missing")
	nistSlice, ok := nistVal.([]interface{})
	require.True(t, ok, "nist tag not a slice")
	assert.Contains(t, nistSlice, "AU-12")
	assert.Contains(t, nistSlice, "SI-4(2)")
}

// --- CCI tags ---

func TestConvertScoutsuiteToHDF_CCITags(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")

	cciVal, ok := req.Tags["cci"]
	require.True(t, ok, "cci tag missing")
	cciSlice, ok := cciVal.([]interface{})
	require.True(t, ok, "cci tag not a slice")
	assert.Greater(t, len(cciSlice), 0)
}

// --- Descriptions ---

func TestConvertScoutsuiteToHDF_DefaultDescription(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "default description missing")
	assert.Contains(t, desc.Data, "CloudTrail is not configured")
}

func TestConvertScoutsuiteToHDF_FixDescription(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-no-cloudwatch-integration has remediation
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-no-cloudwatch-integration")

	desc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, desc, "fix description missing")
	assert.Contains(t, desc.Data, "CloudWatch Logs group")
}

// --- Refs (external references) ---

func TestConvertScoutsuiteToHDF_Refs(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-not-configured carries one references[] URL
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html", *req.Refs[0].URL)
}

func TestConvertScoutsuiteToHDF_RefsAbsent(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-no-cloudwatch-integration has references: null -> no refs emitted
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-no-cloudwatch-integration")
	assert.Nil(t, req.Refs)
}

// --- Source location ---

func TestConvertScoutsuiteToHDF_SourceLocation(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-not-configured carries path "cloudtrail.regions.id"
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req.SourceLocation)
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "cloudtrail.regions.id", *req.SourceLocation.Ref)
	assert.Nil(t, req.SourceLocation.Line, "cloud-resource locus carries no line number")
}

func TestConvertScoutsuiteToHDF_SourceLocationAbsent(t *testing.T) {
	// A finding with no "path" field must yield no sourceLocation.
	input := []byte(`{"account_id":"123","provider_name":"AWS","services":{"svc":{"findings":{"rule-x":{"checked_items":1,"flagged_items":0,"description":"d","level":"warning","rationale":"r","items":[]}}}},"last_run":{"time":"2021-01-01 00:00:00+0000","version":"5.0.0","ruleset_name":"test","ruleset_about":"test"}}`)
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "rule-x")
	assert.Nil(t, req.SourceLocation, "sourceLocation omitted when finding carries no path")
}

// --- Compliance tags ---

func TestConvertScoutsuiteToHDF_ComplianceTag(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-no-cloudwatch-integration carries 3 CIS compliance references
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-no-cloudwatch-integration")

	complianceVal, ok := req.Tags["compliance"]
	require.True(t, ok, "compliance tag missing")
	complianceSlice, ok := complianceVal.([]string)
	require.True(t, ok, "compliance tag not a []string")
	assert.Equal(t, []string{
		"CIS Amazon Web Services Foundations 2.4 (v1.0.0)",
		"CIS Amazon Web Services Foundations 2.4 (v1.1.0)",
		"CIS Amazon Web Services Foundations 2.4 (v1.2.0)",
	}, complianceSlice)
}

func TestConvertScoutsuiteToHDF_ComplianceTagAbsent(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-not-configured has no compliance array -> tag omitted
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")
	_, ok := req.Tags["compliance"]
	assert.False(t, ok, "compliance tag should be omitted when source has none")
}

// --- Title ---

func TestConvertScoutsuiteToHDF_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req.Title)
	assert.Equal(t, "CloudTrail Service Not Configured", *req.Title)
}

// --- Code desc ---

func TestConvertScoutsuiteToHDF_CodeDescDescription(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.Len(t, req.Results, 1)
	assert.Contains(t, req.Results[0].CodeDesc, "CloudTrail Service Not Configured")
}

// --- Message for failed items ---

func TestConvertScoutsuiteToHDF_FailedMessage(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.Len(t, req.Results, 1)
	assert.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "16 flagged items")
}

// --- Message for skipped items ---

func TestConvertScoutsuiteToHDF_NotReviewedMessage(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "cloudtrail-duplicated-global-services-logging")
	require.Len(t, req.Results, 1)
	assert.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "no items were checked")
}

// --- JS variable prefix stripping ---

func TestStripJSPrefix(t *testing.T) {
	input := "scoutsuite_results =\n  {\"key\":\"value\"}"
	result := stripJSPrefix(input)
	assert.Equal(t, "{\"key\":\"value\"}", result)
}

func TestStripJSPrefix_NoPrefix(t *testing.T) {
	input := "{\"key\":\"value\"}"
	result := stripJSPrefix(input)
	assert.Equal(t, "{\"key\":\"value\"}", result)
}

func TestStripJSPrefix_AlternatePrefix(t *testing.T) {
	input := "scoutsuite_results={\"key\":\"value\"}"
	result := stripJSPrefix(input)
	assert.Equal(t, "{\"key\":\"value\"}", result)
}

// --- Impact mapping ---

func TestGetImpact(t *testing.T) {
	assert.Equal(t, 0.7, getImpact("danger"))
	assert.Equal(t, 0.5, getImpact("warning"))
	assert.Equal(t, 0.3, getImpact("unknown"))
	assert.Equal(t, 0.3, getImpact(""))
}

func TestConvertScoutsuiteToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

// countScoutsuiteFindings counts every finding across all services by walking
// the raw ScoutSuite document — deliberately NOT the converter's structs.
// ScoutSuite holds findings as a MAP keyed by rule id under
// services[*].findings, so CountJSONItemsUnderKey (which counts array items)
// does not apply; the emission unit is one requirement per findings map entry
// (collapseFindings flattens with no dedup). The JS variable prefix is stripped
// the same way the converter does before JSON parsing.
func countScoutsuiteFindings(t *testing.T, input []byte) int {
	t.Helper()
	s := string(input)
	if idx := strings.Index(s, "{"); idx > 0 {
		s = s[idx:]
	}
	var doc struct {
		Services map[string]struct {
			Findings map[string]json.RawMessage `json:"findings"`
		} `json:"services"`
	}
	require.NoError(t, json.Unmarshal([]byte(s), &doc), "failed to parse ScoutSuite JSON for anchor count")
	n := 0
	for _, svc := range doc.Services {
		n += len(svc.Findings)
	}
	return n
}

// Ground-truth anchor: the converter emits one requirement per finding across
// all services[*].findings map entries. The count is derived independently of
// the converter's parser, so a silent under-extraction (e.g. dropping a
// service's findings) fails even when Go/TS golden parity agrees.
func TestConvertScoutsuiteToHDF_FindingsAnchor(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countScoutsuiteFindings(t, input),
		"scoutsuite_sample.js: one requirement per services[*].findings entry")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "scoutsuite-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertScoutsuiteToHDF(input, "1.0.0")
	})
}

func TestConvertScoutsuiteToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q expected verificationMethod=automated", req.ID)
	}
}
