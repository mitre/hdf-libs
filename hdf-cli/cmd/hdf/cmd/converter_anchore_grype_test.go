package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureAnchoreGrypeRegistered ensures the Anchore Grype converter is registered.
// Call this at the start of each test since some tests reset the global registry.
func ensureAnchoreGrypeRegistered() {
	RegisterConverter("anchore-grype", "hdf", &anchoreGrypeConverter{})
}

func TestAnchoreGrypeConverter_IsRegistered(t *testing.T) {
	ensureAnchoreGrypeRegistered()

	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Anchore Grype converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "Anchore Grype to HDF", converter.Name())
}

func TestAnchoreGrypeConverter_Convert_Minimal(t *testing.T) {
	ensureAnchoreGrypeRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "anchore-grype-to-hdf", "input/minimal.json"))
	require.NoError(t, err, "Failed to read minimal.json fixture")

	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Failed to get Anchore Grype converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestAnchoreGrypeConverter_Convert_InvalidJSON(t *testing.T) {
	ensureAnchoreGrypeRegistered()

	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Failed to get Anchore Grype converter")

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "anchore grype conversion failed")
}

func TestAnchoreGrypeConverter_Convert_EmptyInput(t *testing.T) {
	ensureAnchoreGrypeRegistered()

	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Failed to get Anchore Grype converter")

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}

func TestAnchoreGrypeConverter_Convert_InvalidStructure(t *testing.T) {
	ensureAnchoreGrypeRegistered()

	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Failed to get Anchore Grype converter")

	// The converter is lenient and will accept a minimal structure, using defaults for missing fields.
	minimalGrype := []byte(`{"descriptor": {"name": "grype"}, "source": {"target": {"userInput": "test"}}, "matches": []}`)
	output, err := converter.Convert(minimalGrype)
	assert.NoError(t, err, "Should handle minimal structure gracefully")
	assert.NotNil(t, output, "Output should not be nil")
	assert.Contains(t, string(output), "\"baselines\"")
}
