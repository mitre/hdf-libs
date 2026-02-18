//nolint:dupl // Converter test files are intentionally structural mirrors of each other.
package cmd

import (
	"os"
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

	inputData, err := os.ReadFile(converterFixturePath(t, "sonarqube-to-hdf", "input/minimal.json"))
	require.NoError(t, err, "Failed to read minimal.json fixture")

	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "Failed to get SonarQube converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestSonarqubeConverter_Convert_InvalidJSON(t *testing.T) {
	ensureSonarqubeRegistered()

	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "Failed to get SonarQube converter")

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "sonarqube conversion failed")
}

func TestSonarqubeConverter_Convert_EmptyInput(t *testing.T) {
	ensureSonarqubeRegistered()

	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "Failed to get SonarQube converter")

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}

func TestSonarqubeConverter_Convert_InvalidStructure(t *testing.T) {
	ensureSonarqubeRegistered()

	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err, "Failed to get SonarQube converter")

	output, err := converter.Convert([]byte(`{"not": "sonarqube"}`))
	assert.Error(t, err, "Should fail on invalid SonarQube structure")
	assert.Nil(t, output, "Output should be nil on error")
}
