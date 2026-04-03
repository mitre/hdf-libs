package msftdefenderendpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
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
		ConverterName:  "msft-defender-endpoint-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertMsftDefenderEndpointToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvert_MissingValueArray(t *testing.T) {
	_, err := ConvertMsftDefenderEndpointToHDF([]byte(`{"foo": "bar"}`), testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or invalid value array")
}

// ---- Minimal fixture conversion ----

func TestConvert_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Minimal fixture has 1 alert → 1 requirement
	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 1)
}

// ---- Sample fixture conversion ----

func TestConvert_Sample(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Sample fixture has 4 alerts → 4 requirements
	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 4)
}

// ---- Status mapping ----

func TestConvert_StatusMapping_New(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// minimal.json has status "new" → Failed
	req := result.Baselines[0].Requirements[0]
	assert.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvert_StatusMapping_InProgress(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Second alert in sample.json has status "inProgress" → Failed
	req := result.Baselines[0].Requirements[1]
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvert_StatusMapping_Resolved_FalsePositive(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Third alert: resolved with classification "falsePositive" → Passed
	req := result.Baselines[0].Requirements[2]
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
}

func TestConvert_StatusMapping_Resolved_TruePositive(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Fourth alert: resolved with classification "truePositive" → Failed
	req := result.Baselines[0].Requirements[3]
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

// ---- Severity mapping ----

func TestConvert_SeverityMapping_High(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// First alert: severity "high" → 0.7
	assert.Equal(t, 0.7, result.Baselines[0].Requirements[0].Impact)
}

func TestConvert_SeverityMapping_Medium(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Second alert: severity "medium" → 0.5
	assert.Equal(t, 0.5, result.Baselines[0].Requirements[1].Impact)
}

func TestConvert_SeverityMapping_Low(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// minimal.json: severity "low" → 0.3
	assert.Equal(t, 0.3, result.Baselines[0].Requirements[0].Impact)
}

func TestConvert_SeverityMapping_Informational(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Third alert: severity "informational" → 0.0
	assert.Equal(t, 0.0, result.Baselines[0].Requirements[2].Impact)
}

// ---- Generator name ----

func TestConvert_GeneratorName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "msft-defender-endpoint-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvert_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Microsoft Defender for Endpoint", *result.Tool.Name)
}

// ---- Target: Host from device evidence ----

func TestConvert_Target_Host(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	target := result.Components[0]
	assert.Equal(t, hdf.Host, target.Type)
	assert.Equal(t, "temp123.middleeast.corp.microsoft.com", target.Name)
	require.NotNil(t, target.FQDN)
	assert.Equal(t, "temp123.middleeast.corp.microsoft.com", *target.FQDN)
	require.NotNil(t, target.OSName)
	assert.Equal(t, "Windows10", *target.OSName)
}

func TestConvert_Target_Deduplicated(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// 4 alerts with 4 different devices → 4 targets
	assert.Len(t, result.Components, 4)
}

// ---- MITRE ATT&CK techniques in tags ----

func TestConvert_MitreTechniques(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	mitre, ok := req.Tags["mitre"].([]interface{})
	require.True(t, ok, "mitre tag should be a slice")
	assert.Len(t, mitre, 3)
	assert.Contains(t, mitre, "T1064")
	assert.Contains(t, mitre, "T1085")
	assert.Contains(t, mitre, "T1220")
}

func TestConvert_NoMitreTechniques(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Third alert has empty mitreTechniques
	req := result.Baselines[0].Requirements[2]
	_, hasMitre := req.Tags["mitre"]
	assert.False(t, hasMitre, "should not have mitre tag when no techniques")
}

// ---- Category tag ----

func TestConvert_CategoryTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "Execution", req.Tags["category"])
}

// ---- Descriptions ----

func TestConvert_Descriptions(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Len(t, req.Descriptions, 2)

	// Default description from alert description
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Contains(t, req.Descriptions[0].Data, "Binaries signed by Microsoft")

	// Fix description from recommendedActions
	assert.Equal(t, "fix", req.Descriptions[1].Label)
	assert.Contains(t, req.Descriptions[1].Data, "Collect artifacts")
}

// ---- Evidence in code_desc ----

func TestConvert_EvidenceInCodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	codeDesc := req.Results[0].CodeDesc
	assert.Contains(t, codeDesc, "Device: temp123.middleeast.corp.microsoft.com")
	assert.Contains(t, codeDesc, "Process:")
	assert.Contains(t, codeDesc, "rundll32.exe")
}

// ---- Classification/determination tags ----

func TestConvert_ClassificationDetermination(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Fourth alert has classification and determination
	req := result.Baselines[0].Requirements[3]
	assert.Equal(t, "truePositive", req.Tags["classification"])
	assert.Equal(t, "malware", req.Tags["determination"])
}

// ---- Checksum ----

func TestConvert_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Alert ID as requirement ID ----

func TestConvert_AlertIDAsRequirementID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "da637472900382838869_1364969609", req.ID)
}

// ---- Empty value array ----

func TestConvert_EmptyValueArray(t *testing.T) {
	input := []byte(`{"value": []}`)
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Baselines[0].Requirements, 0)
}

// ---- Helper: severityToImpact ----

func TestSeverityToImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"high", 0.7},
		{"High", 0.7},
		{"medium", 0.5},
		{"low", 0.3},
		{"informational", 0.0},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.Equal(t, tc.expected, severityToImpact(tc.severity))
		})
	}
}

// ---- Helper: statusToResult ----

func TestStatusToResult(t *testing.T) {
	falsePos := "falsePositive"
	truePos := "truePositive"

	tests := []struct {
		name           string
		status         string
		classification *string
		expected       hdf.ResultStatus
	}{
		{"new", "new", nil, hdf.Failed},
		{"inProgress", "inProgress", nil, hdf.Failed},
		{"resolved_falsePositive", "resolved", &falsePos, hdf.Passed},
		{"resolved_truePositive", "resolved", &truePos, hdf.Failed},
		{"resolved_nil", "resolved", nil, hdf.Failed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, statusToResult(tc.status, tc.classification))
		})
	}
}

// ---- Verify JSON round-trip ----

func TestConvert_JSONRoundTrip(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Marshal to JSON and back to verify structure is valid
	jsonBytes, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotEmpty(t, jsonBytes)

	var roundTrip hdf.HDFResults
	err = json.Unmarshal(jsonBytes, &roundTrip)
	require.NoError(t, err)
	assert.Len(t, roundTrip.Baselines, 1)
	assert.Len(t, roundTrip.Baselines[0].Requirements, 4)
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "msft-defender-endpoint-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertMsftDefenderEndpointToHDF(input, "0.1.0")
	})
}
