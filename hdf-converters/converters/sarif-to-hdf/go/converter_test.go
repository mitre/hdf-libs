package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-schema"
	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertSarifToHDF_Minimal(t *testing.T) {
	// Load minimal fixture
	inputPath := filepath.Join(shared.GetConvertersDir(), "sarif-to-hdf", "fixtures", "input", "minimal.sarif")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.sarif fixture")

	// Convert
	result, err := ConvertSarifToHDF(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, result, "Result should not be empty")

	// Parse result
	var hdfResult hdf.HDFResults
	err = json.Unmarshal(result, &hdfResult)
	require.NoError(t, err, "Should parse HDF JSON")

	// Verify structure
	require.Len(t, hdfResult.Baselines, 1, "Should have 1 baseline")
	baseline := hdfResult.Baselines[0]
	assert.Equal(t, "SARIF", baseline.Name)
	assert.Equal(t, "2.1.0", *baseline.Version)
	require.Len(t, baseline.Requirements, 2, "Should have 2 requirements")

	// Verify first requirement
	req1 := baseline.Requirements[0]
	assert.Equal(t, "RULE-001", req1.ID)
	assert.Equal(t, "buffer/strcpy", *req1.Title)
	assert.Contains(t, req1.Descriptions[0].Data, "Does not check for buffer overflows")
	assert.Equal(t, 0.7, req1.Impact)
	assert.Equal(t, "error", req1.Tags["severity"])
	cwe1, ok := req1.Tags["cwe"].([]interface{})
	require.True(t, ok, "CWE should be interface array")
	assert.Len(t, cwe1, 2)
	require.NotNil(t, req1.SourceLocation, "SourceLocation should not be nil")
	require.NotNil(t, req1.SourceLocation.Ref)
	assert.Equal(t, "src/main.c", *req1.SourceLocation.Ref)
	require.NotNil(t, req1.SourceLocation.Line)
	assert.Equal(t, float64(42), *req1.SourceLocation.Line)
	require.Len(t, req1.Results, 1)
	assert.Equal(t, hdf.Failed, *req1.Results[0].Status)
	assert.Contains(t, req1.Results[0].CodeDesc, "src/main.c")

	// Verify second requirement
	req2 := baseline.Requirements[1]
	assert.Equal(t, "RULE-002", req2.ID)
	assert.Equal(t, "format/printf", *req2.Title)
	assert.Equal(t, 0.5, req2.Impact)
	assert.Equal(t, "warning", req2.Tags["severity"])
}

func TestConvertSarifToHDF_EmptyResults(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "TestTool", "version": "1.0.0" } },
			"results": []
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input))
	require.NoError(t, err, "Should succeed with empty results")

	var hdfResult hdf.HDFResults
	err = json.Unmarshal(result, &hdfResult)
	require.NoError(t, err)

	assert.Len(t, hdfResult.Baselines, 1)
	assert.Len(t, hdfResult.Baselines[0].Requirements, 0)
}

func TestConvertSarifToHDF_MissingLocations(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "TestTool", "version": "1.0.0" } },
			"results": [{
				"ruleId": "TEST-001",
				"level": "error",
				"message": { "text": "test/issue: Test issue description (CWE-79)." },
				"locations": []
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input))
	require.NoError(t, err)

	var hdfResult hdf.HDFResults
	err = json.Unmarshal(result, &hdfResult)
	require.NoError(t, err)

	req := hdfResult.Baselines[0].Requirements[0]
	assert.Nil(t, req.SourceLocation, "Should have no source location when locations array is empty")
	assert.Len(t, req.Results, 0, "Should have no results")
}

func TestImpactMapping(t *testing.T) {
	tests := []struct {
		name          string
		level         string
		expectedImpact float64
	}{
		{"error level", "error", 0.7},
		{"warning level", "warning", 0.5},
		{"note level", "note", 0.3},
		{"missing level", "", 0.1},
		{"unknown level", "unknown", 0.1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := map[string]interface{}{
				"version": "2.1.0",
				"runs": []map[string]interface{}{
					{
						"tool": map[string]interface{}{
							"driver": map[string]string{"name": "Test", "version": "1.0"},
						},
						"results": []map[string]interface{}{
							{
								"ruleId":    "TEST",
								"level":     tt.level,
								"message":   map[string]string{"text": "test: description"},
								"locations": []interface{}{},
							},
						},
					},
				},
			}

			inputBytes, _ := json.Marshal(input)
			result, err := ConvertSarifToHDF(inputBytes)
			require.NoError(t, err)

			var hdfResult hdf.HDFResults
			json.Unmarshal(result, &hdfResult)

			assert.Equal(t, tt.expectedImpact, hdfResult.Baselines[0].Requirements[0].Impact)
		})
	}
}

func TestCweExtraction(t *testing.T) {
	tests := []struct {
		name        string
		messageText string
		expectedCWE []string
	}{
		{
			"comma separated",
			"test: description (CWE-79, CWE-89).",
			[]string{"CWE-79", "CWE-89"},
		},
		{
			"exclamation slash separated",
			"test: description (CWE-119!/CWE-120).",
			[]string{"CWE-119", "CWE-120"},
		},
		{
			"no CWE",
			"test: description without CWE.",
			[]string{},
		},
		{
			"single CWE",
			"test: description (CWE-120).",
			[]string{"CWE-120"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cweIds := extractCweIds(tt.messageText)
			assert.Equal(t, tt.expectedCWE, cweIds)
		})
	}
}

func TestMessageParsing(t *testing.T) {
	tests := []struct {
		name             string
		messageText      string
		expectedTitle    string
		expectedDesc     string
	}{
		{
			"with colon",
			"buffer/strcpy: Does not check for buffer overflows (CWE-120).",
			"buffer/strcpy",
			"Does not check for buffer overflows (CWE-120).",
		},
		{
			"without colon",
			"Simple message without colon",
			"Simple message without colon",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, desc := parseMessage(tt.messageText)
			assert.Equal(t, tt.expectedTitle, title)
			assert.Equal(t, tt.expectedDesc, desc)
		})
	}
}

func TestMultipleLocations(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "Test", "version": "1.0" } },
			"results": [{
				"ruleId": "TEST",
				"level": "error",
				"message": { "text": "test: description (CWE-120)." },
				"locations": [
					{
						"physicalLocation": {
							"artifactLocation": { "uri": "file1.c" },
							"region": { "startLine": 10, "startColumn": 5 }
						}
					},
					{
						"physicalLocation": {
							"artifactLocation": { "uri": "file2.c" },
							"region": { "startLine": 20, "startColumn": 3 }
						}
					}
				]
			}]
		}]
	}`

	result, err := ConvertSarifToHDF([]byte(input))
	require.NoError(t, err)

	var hdfResult hdf.HDFResults
	json.Unmarshal(result, &hdfResult)

	req := hdfResult.Baselines[0].Requirements[0]

	// Should use first location for sourceLocation
	require.NotNil(t, req.SourceLocation, "SourceLocation should not be nil")
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "file1.c", *req.SourceLocation.Ref)
	require.NotNil(t, req.SourceLocation.Line)
	assert.Equal(t, float64(10), *req.SourceLocation.Line)

	// Should have two results
	require.Len(t, req.Results, 2)
	assert.Contains(t, req.Results[0].CodeDesc, "file1.c")
	assert.Contains(t, req.Results[0].CodeDesc, "LINE : 10")
	assert.Contains(t, req.Results[1].CodeDesc, "file2.c")
	assert.Contains(t, req.Results[1].CodeDesc, "LINE : 20")
}

func TestInvalidJSON(t *testing.T) {
	_, err := ConvertSarifToHDF([]byte("not valid json"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SARIF JSON")
}

func TestMissingRuns(t *testing.T) {
	input := `{ "version": "2.1.0" }`
	_, err := ConvertSarifToHDF([]byte(input))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or empty runs field")
}
