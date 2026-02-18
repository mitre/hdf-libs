//nolint:dupl // Converter test files are intentionally structural mirrors of each other.
package cmd

import (
	"os"
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

	inputData, err := os.ReadFile(converterFixturePath(t, "sarif-to-hdf", "input/minimal.sarif"))
	require.NoError(t, err, "Failed to read minimal.sarif fixture")

	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "Failed to get SARIF converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestSarifConverter_Convert_InvalidJSON(t *testing.T) {
	ensureSarifRegistered()

	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "Failed to get SARIF converter")

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "sarif conversion failed")
}

func TestSarifConverter_Convert_EmptyInput(t *testing.T) {
	ensureSarifRegistered()

	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "Failed to get SARIF converter")

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}

func TestSarifConverter_Convert_InvalidStructure(t *testing.T) {
	ensureSarifRegistered()

	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err, "Failed to get SARIF converter")

	output, err := converter.Convert([]byte(`{"not": "sarif"}`))
	assert.Error(t, err, "Should fail on invalid SARIF structure")
	assert.Nil(t, output, "Output should be nil on error")
}
