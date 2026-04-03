package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToXMLConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "xml")
	require.NoError(t, err, "HDF-to-XML converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "HDF to XML", converter.Name())
}

func TestHDFToXMLConverter_Convert_Minimal(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-xml", "input/minimal.json"))
	require.NoError(t, err, "Failed to read minimal.json fixture")

	converter, err := GetConverter("hdf", "xml")
	require.NoError(t, err, "Failed to get HDF-to-XML converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	outputStr := string(output)
	assert.Contains(t, outputStr, "<?xml")
	assert.Contains(t, outputStr, "<HdfResults>")
	assert.Contains(t, outputStr, "</HdfResults>")
	assert.Contains(t, outputStr, "<baseline>")
	assert.Contains(t, outputStr, "<name>Minimal Baseline</name>")
	assert.Contains(t, outputStr, "<id>REQ-001</id>")
	assert.Contains(t, outputStr, "<nist>AC-1</nist>")
}

func TestHDFToXMLConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "xml")
	require.NoError(t, err, "Failed to get HDF-to-XML converter")

	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should error on invalid JSON")
}

func TestHDFToXMLConverter_Convert_MissingBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "xml")
	require.NoError(t, err, "Failed to get HDF-to-XML converter")

	_, err = converter.Convert([]byte(`{"foo": "bar"}`))
	assert.Error(t, err, "Should error on missing baselines field")
	assert.Contains(t, err.Error(), "missing baselines field")
}

func TestHDFToXMLConverter_Convert_EmptyBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "xml")
	require.NoError(t, err, "Failed to get HDF-to-XML converter")

	input := []byte(`{
		"baselines": [],
		"components": [],
		"statistics": { "duration": 0 }
	}`)

	output, err := converter.Convert(input)
	require.NoError(t, err, "Should succeed with empty baselines")
	assert.NotEmpty(t, output, "Output should contain XML structure")

	outputStr := string(output)
	assert.Contains(t, outputStr, "<HdfResults>")
	assert.Contains(t, outputStr, "<baselines>")
}

func TestHDFToXMLConverter_Convert_SpecialCharacters(t *testing.T) {
	converter, err := GetConverter("hdf", "xml")
	require.NoError(t, err, "Failed to get HDF-to-XML converter")

	input := []byte(`{
		"baselines": [{
			"name": "Test & < > \" '",
			"checksum": { "algorithm": "sha256", "value": "abc" },
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
	assert.True(t, strings.Contains(outputStr, "&amp;") || strings.Contains(outputStr, "&#38;"), "Should contain escaped ampersand")
	assert.True(t, strings.Contains(outputStr, "&lt;") || strings.Contains(outputStr, "&#60;"), "Should contain escaped less-than")
	assert.True(t, strings.Contains(outputStr, "&gt;") || strings.Contains(outputStr, "&#62;"), "Should contain escaped greater-than")
}
