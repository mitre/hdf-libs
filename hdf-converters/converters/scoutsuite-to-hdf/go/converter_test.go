package scoutsuite

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
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

func findRequirement(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
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
	assert.Len(t, result.Baselines[0].Requirements, 0)
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
	assert.Equal(t, "JSON", *result.Tool.Format)
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
	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req)
	assert.Equal(t, 0.7, req.Impact)
}

func TestConvertScoutsuiteToHDF_ImpactWarning(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-duplicated-global-services-logging has level "warning"
	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-duplicated-global-services-logging")
	require.NotNil(t, req)
	assert.Equal(t, 0.5, req.Impact)
}

// --- Status mapping ---

func TestConvertScoutsuiteToHDF_StatusFailed(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-not-configured: checked_items=16, flagged_items=16 -> failed
	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvertScoutsuiteToHDF_StatusNotReviewed(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-duplicated-global-services-logging: checked_items=0 -> notReviewed
	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-duplicated-global-services-logging")
	require.NotNil(t, req)
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
	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req)

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
	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-no-cloudwatch-integration")
	require.NotNil(t, req)

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

	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req)

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

	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req)

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "default description missing")
	assert.Contains(t, desc.Data, "CloudTrail is not configured")
}

func TestConvertScoutsuiteToHDF_FixDescription(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// cloudtrail-no-cloudwatch-integration has remediation
	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-no-cloudwatch-integration")
	require.NotNil(t, req)

	desc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, desc, "fix description missing")
	assert.Contains(t, desc.Data, "CloudWatch Logs group")
}

// --- Title ---

func TestConvertScoutsuiteToHDF_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req)
	require.NotNil(t, req.Title)
	assert.Equal(t, "CloudTrail Service Not Configured", *req.Title)
}

// --- Code desc ---

func TestConvertScoutsuiteToHDF_CodeDescDescription(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req)
	require.Len(t, req.Results, 1)
	assert.Contains(t, req.Results[0].CodeDesc, "CloudTrail Service Not Configured")
}

// --- Message for failed items ---

func TestConvertScoutsuiteToHDF_FailedMessage(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-not-configured")
	require.NotNil(t, req)
	require.Len(t, req.Results, 1)
	assert.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "16 flagged items")
}

// --- Message for skipped items ---

func TestConvertScoutsuiteToHDF_NotReviewedMessage(t *testing.T) {
	input := loadFixture(t, "input/scoutsuite_sample.js")
	result, err := ConvertScoutsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "cloudtrail-duplicated-global-services-logging")
	require.NotNil(t, req)
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

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "scoutsuite-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertScoutsuiteToHDF(input, "0.1.0")
	})
}
