package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToXCCDFConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "xccdf")
	require.NoError(t, err, "HDF-to-XCCDF converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "HDF to XCCDF", converter.Name())
}

func TestHDFToXCCDFConverter_Convert_Minimal(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-xccdf", "input/minimal.json"))
	require.NoError(t, err, "Failed to read minimal.json fixture")

	converter, err := GetConverter("hdf", "xccdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	outputStr := string(output)
	assert.Contains(t, outputStr, "<?xml")
	assert.Contains(t, outputStr, `xmlns="http://checklists.nist.gov/xccdf/1.2"`)
	assert.Contains(t, outputStr, "<Benchmark")
	assert.Contains(t, outputStr, "</Benchmark>")
	assert.Contains(t, outputStr, "<Rule")
	assert.Contains(t, outputStr, "<TestResult")
	assert.Contains(t, outputStr, "<target>Test Target</target>")
	assert.Contains(t, outputStr, "<result>fail</result>")
	assert.Contains(t, outputStr, "<result>pass</result>")
}

func TestHDFToXCCDFConverter_Convert_StigRhel7(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-xccdf", "input/stig-rhel7.json"))
	require.NoError(t, err, "Failed to read stig-rhel7.json fixture")

	converter, err := GetConverter("hdf", "xccdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	outputStr := string(output)

	// CCI idents preserved
	assert.Contains(t, outputStr, "CCI-000048")
	assert.Contains(t, outputStr, `system="http://cyber.mil/cci"`)

	// Severities mapped
	assert.Contains(t, outputStr, `severity="medium"`)
	assert.Contains(t, outputStr, `severity="high"`)
	assert.Contains(t, outputStr, `severity="low"`)

	// Target info
	assert.Contains(t, outputStr, "<target>localhost.localdomain</target>")
	assert.Contains(t, outputStr, "<target-address>127.0.0.1</target-address>")
}

func TestHDFToXCCDFConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "xccdf")
	require.NoError(t, err)

	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should error on invalid JSON")
}

func TestHDFToXCCDFConverter_Convert_MissingBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "xccdf")
	require.NoError(t, err)

	_, err = converter.Convert([]byte(`{"foo": "bar"}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing baselines")
}

func TestHDFToXCCDFConverter_Convert_EmptyInput(t *testing.T) {
	converter, err := GetConverter("hdf", "xccdf")
	require.NoError(t, err)

	_, err = converter.Convert([]byte(""))
	assert.Error(t, err)
}

func TestHDFToXCCDFConverter_Convert_SpecialCharacters(t *testing.T) {
	converter, err := GetConverter("hdf", "xccdf")
	require.NoError(t, err)

	input := []byte(`{
		"baselines": [{
			"name": "Test & < > \" '",
			"requirements": [{
				"id": "REQ-001",
				"title": "Description with <tags> & special chars",
				"descriptions": [{ "label": "default", "data": "Data" }],
				"impact": 0.5,
				"tags": {},
				"results": [{ "status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z" }]
			}]
		}],
		"statistics": {}
	}`)

	output, err := converter.Convert(input)
	require.NoError(t, err, "Should succeed with special characters")

	outputStr := string(output)
	assert.True(t, strings.Contains(outputStr, "&amp;") || strings.Contains(outputStr, "&#38;"))
	assert.True(t, strings.Contains(outputStr, "&lt;") || strings.Contains(outputStr, "&#60;"))
}
