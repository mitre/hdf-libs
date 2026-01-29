package cmd

import (
	"os"
	"path/filepath"
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
	// Load minimal fixture
	inputPath := hdfToCSVFixturePath(t, "input/minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.json fixture")

	// Get converter
	converter, err := GetConverter("hdf", "csv")
	require.NoError(t, err, "Failed to get HDF-to-CSV converter")

	// Convert
	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	// Verify it's valid CSV with expected content
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
		"targets": [],
		"statistics": { "duration": 0 }
	}`)

	output, err := converter.Convert(input)
	require.NoError(t, err, "Should succeed with empty baselines")
	assert.Empty(t, output, "Output should be empty")
}

func hdfToCSVFixturePath(t *testing.T, name string) string {
	t.Helper()

	cwd, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")

	// From cmd/hdf/cmd, navigate to hdf-converters/converters/hdf-to-csv/fixtures
	fixturePath := filepath.Join(cwd, "..", "..", "..", "..", "hdf-converters", "converters", "hdf-to-csv", "fixtures", name)
	fixturePath = filepath.Clean(fixturePath)

	// Check if file exists
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		// Try alternative path (when running from different directory)
		altPath := filepath.Join("..", "..", "..", "..", "hdf-converters", "converters", "hdf-to-csv", "fixtures", name)
		if absPath, err := filepath.Abs(altPath); err == nil {
			if _, err := os.Stat(absPath); err == nil {
				return absPath
			}
		}
		t.Skipf("Fixture not found: %s", fixturePath)
	}

	return fixturePath
}
