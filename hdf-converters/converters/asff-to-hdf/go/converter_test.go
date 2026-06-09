package asff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "asff-to-hdf", "fixtures", "input", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func firstResult(t *testing.T, result *hdf.HDFResults) *hdf.RequirementResult {
	t.Helper()
	require.NotNil(t, result)
	require.Len(t, result.Baselines, 1)
	require.NotEmpty(t, result.Baselines[0].Requirements)
	require.NotEmpty(t, result.Baselines[0].Requirements[0].Results)
	return &result.Baselines[0].Requirements[0].Results[0]
}

// ---- envelope / parsing ----

func TestConvert_Default_Minimal(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "minimal.json"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "asff-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "AWS Security Finding Format", *result.Tool.Name)
	require.NotNil(t, result.Timestamp)

	require.Len(t, result.Baselines, 1)
	bl := result.Baselines[0]
	assert.NotEmpty(t, bl.Name)
	require.Len(t, bl.Requirements, 1)

	req := bl.Requirements[0]
	assert.NotEmpty(t, req.ID, "requirement ID must be set from GeneratorId/Control")
	require.NotNil(t, req.Title)
	assert.Contains(t, *req.Title, "root", "title from ASFF Title field")
	require.NotEmpty(t, req.Descriptions)
	assert.Equal(t, "default", req.Descriptions[0].Label)

	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status, "first finding has Compliance.Status=FAILED")
	assert.Contains(t, req.Results[0].CodeDesc, "Resources:")
}

func TestConvert_Default_BareArrayInput(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "bare-array.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
}

func TestConvert_Default_SingleFindingInput(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "single.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
}

// ---- empty input (Step 4e) ----

func TestConvert_EmptyFindings(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "empty.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1, "synthesizes one no-findings placeholder")

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "asff-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "ASFF")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

// ---- consolidation ----

func TestConvert_Default_Consolidation(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "multi-resource.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1, "3 findings sharing GeneratorId consolidate into 1 requirement")
	assert.Len(t, result.Baselines[0].Requirements[0].Results, 3, "each source finding becomes a Result")
}

// ---- suppressed ----

func TestConvert_Default_SuppressedZeroImpact(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "suppressed.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)
	assert.Equal(t, 0.0, result.Baselines[0].Requirements[0].Impact, "Workflow.Status=SUPPRESSED forces impact 0")
}

// ---- component ----

func TestConvert_ComponentFromAwsAccountId(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "minimal.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Components, 1)
	assert.Equal(t, hdf.CloudAccount, result.Components[0].Type)
	assert.Contains(t, result.Components[0].Name, "123456789123")
}

// ---- SecurityHub case dispatch ----

func TestConvert_SecurityHub_DispatchedByProductArn(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "securityhub.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	bl := result.Baselines[0]
	// SecurityHub case derives baseline name from StandardsControlArn — must mention CIS / Foundations / v1.2.0
	require.NotNil(t, bl.Title)
	assert.Contains(t, *bl.Title, "v1.2.0")
}

func TestConvert_SecurityHub_FindingIdFromRuleId(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "minimal.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)
	// SecurityHub case prefers ProductFields.RuleId (CIS) when StandardsControlArn lookup table not supplied.
	// minimal.json has ProductFields.RuleId="1.1".
	assert.Equal(t, "1.1", result.Baselines[0].Requirements[0].ID, "SecurityHub case derives ID from ProductFields.RuleId")
}

func TestConvert_SecurityHub_InformationalBumpedToMedium(t *testing.T) {
	// Build a SecurityHub-arn finding with Severity.Label=INFORMATIONAL
	input := []byte(`{"Findings": [{
		"SchemaVersion": "2018-10-08",
		"Id": "test-id",
		"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
		"GeneratorId": "test/gen",
		"AwsAccountId": "123456789123",
		"Title": "Test informational finding",
		"Description": "Should be bumped to medium impact",
		"Severity": {"Label": "INFORMATIONAL", "Normalized": 0},
		"Resources": [{"Type": "AwsAccount", "Id": "AWS::::Account:123456789123"}],
		"ProductFields": {"RuleId": "test-rule"},
		"Compliance": {"Status": "FAILED"},
		"UpdatedAt": "2026-01-01T00:00:00Z",
		"Types": ["Test"]
	}]}`)
	result, err := ConvertAsffToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)
	assert.InDelta(t, 0.5, result.Baselines[0].Requirements[0].Impact, 0.001, "SecurityHub bumps INFORMATIONAL to MEDIUM=0.5")
}

func TestConvert_SecurityHub_NISTFromAwsConfigRule(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "config-rule.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)
	tags := result.Baselines[0].Requirements[0].Tags
	require.NotNil(t, tags)
	nistRaw, ok := tags["nist"]
	require.True(t, ok, "config-rule finding must produce NIST tags via awsconfig mapping")
	nist, ok := nistRaw.([]string)
	require.True(t, ok)
	// s3-bucket-public-read-prohibited maps to AC-3|AC-4|AC-6|AC-21(b)|SC-7|SC-7(3)
	assert.Contains(t, nist, "AC-3")
	assert.Contains(t, nist, "SC-7")
}

// ---- compliance status mapping ----

func TestConvert_ComplianceStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   hdf.ResultStatus
	}{
		{"passed", "PASSED", hdf.Passed},
		{"failed", "FAILED", hdf.Failed},
		{"warning", "WARNING", hdf.NotReviewed},
		{"not_available", "NOT_AVAILABLE", hdf.NotReviewed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Patch minimal.json's Compliance.Status
			var doc map[string]any
			require.NoError(t, json.Unmarshal(fixtureBytes(t, "minimal.json"), &doc))
			findings := doc["Findings"].([]any)
			f := findings[0].(map[string]any)
			f["Compliance"] = map[string]any{"Status": tc.status}
			patched, err := json.Marshal(doc)
			require.NoError(t, err)

			result, err := ConvertAsffToHDF(patched, converterVersion)
			require.NoError(t, err)
			res := firstResult(t, result)
			assert.Equal(t, tc.want, res.Status)
		})
	}
}

func TestConvert_MissingComplianceStatusDefaultsToFailed(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal(fixtureBytes(t, "minimal.json"), &doc))
	findings := doc["Findings"].([]any)
	f := findings[0].(map[string]any)
	delete(f, "Compliance")
	patched, _ := json.Marshal(doc)

	result, err := ConvertAsffToHDF(patched, converterVersion)
	require.NoError(t, err)
	assert.Equal(t, hdf.Failed, firstResult(t, result).Status)
}

// ---- v3.2 classification fields (Step 4d) ----

func TestConvert_VerificationMethodIsAutomated(t *testing.T) {
	result, err := ConvertAsffToHDF(fixtureBytes(t, "config-rule.json"), converterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	require.NotNil(t, req.VerificationMethod, "ASFF is by-provenance automated-scanner output")
	assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod)
}

func TestConvert_ControlTypeFromNISTTags(t *testing.T) {
	// config-rule fixture has real NIST tags (AC-3, AC-4, ...) — ControlType should resolve
	result, err := ConvertAsffToHDF(fixtureBytes(t, "config-rule.json"), converterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.NotNil(t, req.ControlType, "real NIST tags → DeriveControlTypeFromTags non-nil")
}

// ---- error paths ----

func TestConvert_InvalidJSON(t *testing.T) {
	_, err := ConvertAsffToHDF([]byte("not valid json"), converterVersion)
	require.Error(t, err)
}

func TestConvert_EmptyInput(t *testing.T) {
	_, err := ConvertAsffToHDF([]byte(""), converterVersion)
	require.Error(t, err)
}
