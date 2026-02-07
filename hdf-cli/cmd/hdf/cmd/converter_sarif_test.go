package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureSarifRegistered ensures the SARIF converter is registered.
// Call this at the start of each test since some tests reset the global registry.
func ensureSarifRegistered() {
	RegisterConverter("sarif", "hdf", &sarifConverter{})
}

func TestSarifConverter_IsRegistered(t *testing.T) {
	ensureSarifRegistered()

	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "SARIF converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "SARIF to HDF", converter.Name())
}

func TestSarifConverter_Convert_Minimal(t *testing.T) {
	ensureSarifRegistered()

	// Load minimal fixture
	inputPath := sarifFixturePath(t, "input/minimal.sarif")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.sarif fixture")

	// Get converter
	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "Failed to get SARIF converter")

	// Convert
	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	// Verify it's valid JSON with HDF structure
	assert.Contains(t, string(output), "\"baselines\"")
	assert.Contains(t, string(output), "\"generator\"")
	assert.Contains(t, string(output), "\"timestamp\"")
}

func TestSarifConverter_Convert_InvalidJSON(t *testing.T) {
	ensureSarifRegistered()

	// Get converter
	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "Failed to get SARIF converter")

	// Try to convert invalid JSON
	invalidData := []byte("not valid json")
	output, err := converter.Convert(invalidData)

	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "sarif conversion failed")
}

func TestSarifConverter_Convert_EmptyInput(t *testing.T) {
	ensureSarifRegistered()

	// Get converter
	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "Failed to get SARIF converter")

	// Try to convert empty input
	emptyData := []byte("")
	output, err := converter.Convert(emptyData)

	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}

func TestSarifConverter_Convert_InvalidStructure(t *testing.T) {
	ensureSarifRegistered()

	// Get converter
	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "Failed to get SARIF converter")

	// Valid JSON but invalid SARIF structure
	invalidSarif := []byte(`{"not": "sarif"}`)
	output, err := converter.Convert(invalidSarif)

	assert.Error(t, err, "Should fail on invalid SARIF structure")
	assert.Nil(t, output, "Output should be nil on error")
}

// Helper function to get path to SARIF fixture files.
// Navigates from cmd/hdf/cmd/ to converters/sarif-to-hdf/fixtures/.
func sarifFixturePath(t *testing.T, name string) string {
	t.Helper()

	// Get the current working directory
	cwd, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")

	// Navigate to the converters directory
	// From cmd/hdf/cmd, go up 3 levels to hdf-cli, then up 1 to hdf-libs,
	// then into hdf-converters/converters/sarif-to-hdf/fixtures
	fixturePath := filepath.Join(cwd, "..", "..", "..", "..", "hdf-converters", "converters", "sarif-to-hdf", "fixtures", name)

	// Clean the path
	fixturePath = filepath.Clean(fixturePath)

	return fixturePath
}
