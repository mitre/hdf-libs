package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureGrypeRegistered ensures the Grype converter is registered.
// Call this at the start of each test since some tests reset the global registry.
func ensureGrypeRegistered() {
	RegisterConverter("grype", "hdf", &grypeConverter{})
}

func TestGrypeConverter_IsRegistered(t *testing.T) {
	ensureGrypeRegistered()

	converter, err := GetConverter("grype", "hdf")
	require.NoError(t, err, "Grype converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "Grype to HDF", converter.Name())
}

func TestGrypeConverter_Convert_Minimal(t *testing.T) {
	ensureGrypeRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "grype-to-hdf", "input/amazon.json"))
	require.NoError(t, err, "Failed to read amazon.json fixture")

	converter, err := GetConverter("grype", "hdf")
	require.NoError(t, err, "Failed to get Grype converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestGrypeConverter_Convert_InvalidJSON(t *testing.T) {
	ensureGrypeRegistered()

	converter, err := GetConverter("grype", "hdf")
	require.NoError(t, err, "Failed to get Grype converter")

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "grype conversion failed")
}

func TestGrypeConverter_Convert_EmptyInput(t *testing.T) {
	ensureGrypeRegistered()

	converter, err := GetConverter("grype", "hdf")
	require.NoError(t, err, "Failed to get Grype converter")

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}

func TestGrypeConverter_Convert_InvalidStructure(t *testing.T) {
	ensureGrypeRegistered()

	converter, err := GetConverter("grype", "hdf")
	require.NoError(t, err, "Failed to get Grype converter")

	// The converter is lenient and will accept a minimal structure, using defaults for missing fields.
	minimalGrype := []byte(`{"descriptor": {"name": "grype"}, "source": {"target": {"userInput": "test"}}, "matches": []}`)
	output, err := converter.Convert(minimalGrype)
	assert.NoError(t, err, "Should handle minimal structure gracefully")
	assert.NotNil(t, output, "Output should not be nil")
	assert.Contains(t, string(output), "\"baselines\"")
}
