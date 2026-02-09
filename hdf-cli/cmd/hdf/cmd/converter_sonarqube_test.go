package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureSonarqubeRegistered ensures the SonarQube converter is registered.
// Call this at the start of each test since some tests reset the global registry.
func ensureSonarqubeRegistered() {
	RegisterConverter("sonarqube", "hdf", &sonarqubeConverter{})
}

func TestSonarqubeConverter_IsRegistered(t *testing.T) {
	ensureSonarqubeRegistered()

	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "SonarQube converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "SonarQube to HDF", converter.Name())
}

func TestSonarqubeConverter_Convert_Minimal(t *testing.T) {
	ensureSonarqubeRegistered()

	// Load minimal fixture
	inputPath := sonarqubeFixturePath(t, "input/minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.json fixture")

	// Get converter
	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "Failed to get SonarQube converter")

	// Convert
	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	// Verify it's valid JSON with HDF structure
	assert.Contains(t, string(output), "\"baselines\"")
	assert.Contains(t, string(output), "\"generator\"")
	assert.Contains(t, string(output), "\"timestamp\"")
}

func TestSonarqubeConverter_Convert_InvalidJSON(t *testing.T) {
	ensureSonarqubeRegistered()

	// Get converter
	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "Failed to get SonarQube converter")

	// Try to convert invalid JSON
	invalidData := []byte("not valid json")
	output, err := converter.Convert(invalidData)

	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "sonarqube conversion failed")
}

func TestSonarqubeConverter_Convert_EmptyInput(t *testing.T) {
	ensureSonarqubeRegistered()

	// Get converter
	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "Failed to get SonarQube converter")

	// Try to convert empty input
	emptyData := []byte("")
	output, err := converter.Convert(emptyData)

	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}

func TestSonarqubeConverter_Convert_InvalidStructure(t *testing.T) {
	ensureSonarqubeRegistered()

	// Get converter
	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "Failed to get SonarQube converter")

	// Valid JSON but invalid SonarQube structure
	invalidSonarqube := []byte(`{"not": "sonarqube"}`)
	output, err := converter.Convert(invalidSonarqube)

	assert.Error(t, err, "Should fail on invalid SonarQube structure")
	assert.Nil(t, output, "Output should be nil on error")
}

// Helper function to get path to SonarQube fixture files.
// Navigates from cmd/hdf/cmd/ to converters/sonarqube-to-hdf/fixtures/.
func sonarqubeFixturePath(t *testing.T, name string) string {
	t.Helper()

	// Get the current working directory
	cwd, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")

	// Navigate to the converters directory
	// From cmd/hdf/cmd, go up 3 levels to hdf-cli, then up 1 to hdf-libs,
	// then into hdf-converters/converters/sonarqube-to-hdf/fixtures
	fixturePath := filepath.Join(cwd, "..", "..", "..", "..", "hdf-converters", "converters", "sonarqube-to-hdf", "fixtures", name)

	// Clean the path
	fixturePath = filepath.Clean(fixturePath)

	return fixturePath
}
