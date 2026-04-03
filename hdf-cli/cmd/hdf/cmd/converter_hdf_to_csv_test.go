package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToCSVConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "csv")
	require.NoError(t, err, "HDF-to-CSV converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "HDF to CSV", converter.Name())
}

func TestHDFToCSVConverter_Convert_Minimal(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-csv", "input/minimal.json"))
	require.NoError(t, err, "Failed to read minimal.json fixture")

	converter, err := GetConverter("hdf", "csv")
	require.NoError(t, err, "Failed to get HDF-to-CSV converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	outputStr := string(output)
	assert.Contains(t, outputStr, "Baseline ID,Baseline Version")
	assert.Contains(t, outputStr, "Example STIG Baseline")
	assert.Contains(t, outputStr, "SV-123456")
	assert.Contains(t, outputStr, "passed")
}

func TestHDFToCSVConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "csv")
	require.NoError(t, err, "Failed to get HDF-to-CSV converter")

	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should error on invalid JSON")
}

func TestHDFToCSVConverter_Convert_EmptyBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "csv")
	require.NoError(t, err, "Failed to get HDF-to-CSV converter")

	input := []byte(`{
		"baselines": [],
		"components": [],
		"statistics": { "duration": 0 }
	}`)

	output, err := converter.Convert(input)
	require.NoError(t, err, "Should succeed with empty baselines")
	assert.Empty(t, output, "Output should be empty")
}
