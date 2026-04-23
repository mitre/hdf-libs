package msftdefendercloud

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

// ---- Error handling ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "msft-defender-cloud-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertMsftDefenderCloudToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvert_MissingValueArray(t *testing.T) {
	_, err := ConvertMsftDefenderCloudToHDF([]byte(`{}`), testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or invalid value array")
}

func TestConvert_InvalidValueType(t *testing.T) {
	_, err := ConvertMsftDefenderCloudToHDF([]byte(`{"value":"notarray"}`), testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

// ---- Minimal fixture conversion ----

func TestConvert_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Minimal fixture has 2 assessments → 2 requirements
	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 2)
}

// ---- Sample fixture conversion ----

func TestConvert_Sample(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Sample fixture has 6 assessments → 6 requirements
	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 6)
}

// ---- Status mapping ----

func TestConvert_StatusMapping(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	// First assessment is Healthy → Passed
	req0 := result.Baselines[0].Requirements[0]
	assert.Equal(t, hdf.Passed, req0.Results[0].Status)

	// Second assessment is Unhealthy → Failed
	req1 := result.Baselines[0].Requirements[1]
	assert.Equal(t, hdf.Failed, req1.Results[0].Status)
}

func TestConvert_StatusMapping_NotApplicable(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	// Fifth assessment (index 4) is NotApplicable
	req4 := result.Baselines[0].Requirements[4]
	assert.Equal(t, hdf.NotApplicable, req4.Results[0].Status)
}

// ---- Severity mapping ----

func TestConvert_SeverityMapping_High(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	// Second assessment has severity High → 0.7
	req1 := result.Baselines[0].Requirements[1]
	assert.Equal(t, 0.7, req1.Impact)
}

func TestConvert_SeverityMapping_Medium(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	// First assessment has severity Medium → 0.5
	req0 := result.Baselines[0].Requirements[0]
	assert.Equal(t, 0.5, req0.Impact)
}

func TestConvert_SeverityMapping_Low(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	// Fifth assessment (index 4) has severity Low → 0.3
	req4 := result.Baselines[0].Requirements[4]
	assert.Equal(t, 0.3, req4.Impact)
}

// ---- Generator name ----

func TestConvert_GeneratorName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "msft-defender-cloud-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvert_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Microsoft Defender for Cloud", *result.Tool.Name)
}

// ---- Target: CloudAccount with subscription ID ----

func TestConvert_Target(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components, "should have at least one target")
	target := result.Components[0]

	assert.Equal(t, hdf.CloudAccount, target.Type)
	assert.Contains(t, target.Name, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	require.NotNil(t, target.AccountID)
	assert.Equal(t, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", *target.AccountID)
	require.NotNil(t, target.Provider)
	assert.Equal(t, hdf.Azure, *target.Provider)
}

// ---- MITRE ATT&CK tags ----

func TestConvert_MITREATTCKTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req0 := result.Baselines[0].Requirements[0]

	tactics, ok := req0.Tags["tactics"].([]interface{})
	require.True(t, ok, "tactics should be a slice")
	assert.Contains(t, tactics, "Discovery")
	assert.Contains(t, tactics, "Exfiltration")

	techniques, ok := req0.Tags["techniques"].([]interface{})
	require.True(t, ok, "techniques should be a slice")
	assert.Contains(t, techniques, "T1046")
	assert.Contains(t, techniques, "T1530")
}

// ---- Categories in tags ----

func TestConvert_Categories(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req0 := result.Baselines[0].Requirements[0]

	categories, ok := req0.Tags["categories"].([]interface{})
	require.True(t, ok, "categories should be a slice")
	assert.Contains(t, categories, "Networking")
}

// ---- Descriptions ----

func TestConvert_Descriptions(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req0 := result.Baselines[0].Requirements[0]

	var defaultDesc, fixDesc *hdf.Description
	for i := range req0.Descriptions {
		switch req0.Descriptions[i].Label {
		case "default":
			defaultDesc = &req0.Descriptions[i]
		case "fix":
			fixDesc = &req0.Descriptions[i]
		}
	}

	require.NotNil(t, defaultDesc, "should have a default description")
	assert.Contains(t, defaultDesc.Data, "Private links enforce secure communication")

	require.NotNil(t, fixDesc, "should have a fix description")
	assert.Contains(t, fixDesc.Data, "private endpoint")
}

// ---- Requirement ID from assessment name (GUID) ----

func TestConvert_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req0 := result.Baselines[0].Requirements[0]
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", req0.ID)
}

// ---- Resource details in code_desc ----

func TestConvert_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req0 := result.Baselines[0].Requirements[0]
	assert.Contains(t, req0.Results[0].CodeDesc, "storageAccounts/mystorageacct")
}

// ---- Checksum ----

func TestConvert_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Empty value array ----

func TestConvert_EmptyValueArray(t *testing.T) {
	input := []byte(`{"value":[]}`)
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Baselines[0].Requirements)
}

// ---- Title from displayName ----

func TestConvert_Title(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req0 := result.Baselines[0].Requirements[0]
	require.NotNil(t, req0.Title)
	assert.Equal(t, "Storage account should use a private link connection", *req0.Title)
}

// ---- Unhealthy status message ----

func TestConvert_UnhealthyMessage(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req1 := result.Baselines[0].Requirements[1]
	require.NotNil(t, req1.Results[0].Message)
	assert.Contains(t, *req1.Results[0].Message, "Azure Disk Encryption is not enabled")
}

// ---- Helper: extractSubscriptionID ----

func TestExtractSubscriptionID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/rg", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
		{"/SUBSCRIPTIONS/UPPER-CASE-ID/resourceGroups/rg", "UPPER-CASE-ID"},
		{"no-subscriptions-here", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, extractSubscriptionID(tc.input))
		})
	}
}

// ---- mapStatus ----

func TestMapStatus(t *testing.T) {
	tests := []struct {
		code     string
		expected hdf.ResultStatus
	}{
		{"Healthy", hdf.Passed},
		{"healthy", hdf.Passed},
		{"Unhealthy", hdf.Failed},
		{"unhealthy", hdf.Failed},
		{"NotApplicable", hdf.NotApplicable},
		{"notapplicable", hdf.NotApplicable},
		{"Unknown", hdf.NotReviewed},
		{"", hdf.NotReviewed},
	}
	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapStatus(tc.code))
		})
	}
}

// ---- Timestamp and baseline name ----

func TestConvert_TimestampAndBaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	assert.NotNil(t, result.Timestamp)
	assert.Equal(t, "Microsoft Defender for Cloud Assessments", result.Baselines[0].Name)
}

// ---- Verify JSON round-trip produces valid output ----

func TestConvert_JSONRoundTrip(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)

	var roundTrip hdf.HDFResults
	err = json.Unmarshal(jsonBytes, &roundTrip)
	require.NoError(t, err)
	assert.Len(t, roundTrip.Baselines[0].Requirements, 2)
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "msft-defender-cloud-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertMsftDefenderCloudToHDF(input, "0.1.0")
	})
}
