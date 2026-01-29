package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNessusConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Nessus converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "Nessus to HDF", converter.Name())
}

func TestNessusConverter_Convert_Minimal(t *testing.T) {
	// Load minimal fixture
	inputPath := nessusFixturePath(t, "input/minimal.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.nessus fixture")

	// Get converter
	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Failed to get Nessus converter")

	// Convert
	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	// Verify it's valid JSON
	assert.Contains(t, string(output), "\"baselines\"")
	assert.Contains(t, string(output), "\"targets\"")
	assert.Contains(t, string(output), "\"generator\"")
}

func TestNessusConverter_Convert_Compliance(t *testing.T) {
	// Load compliance fixture
	inputPath := nessusFixturePath(t, "input/compliance.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read compliance.nessus fixture")

	// Get converter
	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Failed to get Nessus converter")

	// Convert
	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	// Verify it contains compliance-specific data
	assert.Contains(t, string(output), "\"baselines\"")
	assert.Contains(t, string(output), "DISA STIG")
}

func TestNessusConverter_Convert_InvalidXML(t *testing.T) {
	// Get converter
	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Failed to get Nessus converter")

	// Try to convert invalid XML
	invalidData := []byte("not valid xml")
	output, err := converter.Convert(invalidData)

	assert.Error(t, err, "Should fail on invalid XML")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "nessus conversion failed")
}

func TestNessusConverter_Convert_EmptyInput(t *testing.T) {
	// Get converter
	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Failed to get Nessus converter")

	// Try to convert empty input
	emptyData := []byte("")
	output, err := converter.Convert(emptyData)

	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}

// Helper function to get path to Nessus fixture files.
// Navigates from cmd/hdf/cmd/ to converters/nessus/fixtures/.
func nessusFixturePath(t *testing.T, name string) string {
	t.Helper()

	// Get the current working directory
	cwd, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")

	// Navigate to the converters directory
	// From cmd/hdf/cmd, go up 3 levels to hdf-cli, then up 1 to hdf-libs,
	// then into hdf-converters/converters/nessus/fixtures
	fixturePath := filepath.Join(cwd, "..", "..", "..", "..", "hdf-converters", "converters", "nessus", "fixtures", name)

	// Clean the path
	fixturePath = filepath.Clean(fixturePath)

	return fixturePath
}
