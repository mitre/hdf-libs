package msftdefendercloud

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

// ---- Policy definition ID tag ----

func TestConvert_PolicyDefinitionIDTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req0 := result.Baselines[0].Requirements[0]
	pdid, ok := req0.Tags["policy_definition_id"].(string)
	require.True(t, ok, "policy_definition_id should be a string")
	assert.Equal(t, "/providers/Microsoft.Authorization/policyDefinitions/aaaa1111-bbbb-2222-cccc-3333dddd4444", pdid)
}

func TestConvert_PolicyDefinitionIDTag_Absent(t *testing.T) {
	input := []byte(`{"value":[{"id":"/subscriptions/sub1/providers/Microsoft.Security/assessments/nopolicy","name":"nopolicy","type":"Microsoft.Security/assessments","properties":{"displayName":"No policy","resourceDetails":{"source":"Azure","id":"/subscriptions/sub1/res"},"status":{"code":"Healthy"},"metadata":{"displayName":"No policy","severity":"Low"}}}]}`)
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)

	req0 := result.Baselines[0].Requirements[0]
	_, ok := req0.Tags["policy_definition_id"]
	assert.False(t, ok, "policy_definition_id should be omitted when source field is absent")
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

// ---- Empty value array — synthesizes a passed placeholder ----

func TestConvert_EmptyValueArray(t *testing.T) {
	input := []byte(`{"value":[]}`)
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "msft-defender-cloud-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Microsoft Defender for Cloud")
	assert.Contains(t, req.Results[0].CodeDesc, "Unknown")
}

func TestConvert_EmptyFixture(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "msft-defender-cloud-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Microsoft Defender for Cloud")
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
	// Defender for Cloud export carries no scan time.
	shared.RunSnapshotTests(t, "msft-defender-cloud-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertMsftDefenderCloudToHDF(input, "1.0.0")
	}, "*")
}

// countDistinctAssessmentNames counts distinct value[].name GUIDs in the raw
// Azure assessments export, generically (no converter structs). The converter's
// emission unit is one requirement per DISTINCT assessment name — it groups
// value[] entries by name — so a plain array-length count would over-count if
// two entries shared a name. Counting distinct names captures the true unit.
func countDistinctAssessmentNames(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "count distinct assessment names: invalid JSON")
	seen := map[string]struct{}{}
	for _, a := range doc.Value {
		seen[a.Name] = struct{}{}
	}
	return len(seen)
}

// Ground-truth anchor: one requirement per distinct value[].name in the raw
// export, counted independently of the converter (see shared/go/anchor.go).
// Guards against silent under-extraction that TS/Go golden parity cannot detect.
func TestConvert_AssessmentAnchor(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countDistinctAssessmentNames(t, input),
		"sample.json: one requirement per distinct value[].name assessment")
}

func TestConvertMsftDefenderCloud_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderCloudToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: Defender for Cloud assessments are automated", req.ID)
	}
}
