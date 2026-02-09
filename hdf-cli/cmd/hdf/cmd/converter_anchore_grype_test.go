package cmd

import (
	"os"
	"path/filepath"
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

	// Load minimal fixture
	inputPath := anchoreGrypeFixturePath(t, "input/minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.json fixture")

	// Get converter
	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Failed to get Anchore Grype converter")

	// Convert
	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	// Verify it's valid JSON with HDF structure
	assert.Contains(t, string(output), "\"baselines\"")
	assert.Contains(t, string(output), "\"generator\"")
	assert.Contains(t, string(output), "\"timestamp\"")
}

func TestAnchoreGrypeConverter_Convert_InvalidJSON(t *testing.T) {
	ensureAnchoreGrypeRegistered()

	// Get converter
	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Failed to get Anchore Grype converter")

	// Try to convert invalid JSON
	invalidData := []byte("not valid json")
	output, err := converter.Convert(invalidData)

	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "anchore grype conversion failed")
}

func TestAnchoreGrypeConverter_Convert_EmptyInput(t *testing.T) {
	ensureAnchoreGrypeRegistered()

	// Get converter
	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Failed to get Anchore Grype converter")

	// Try to convert empty input
	emptyData := []byte("")
	output, err := converter.Convert(emptyData)

	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}

func TestAnchoreGrypeConverter_Convert_InvalidStructure(t *testing.T) {
	ensureAnchoreGrypeRegistered()

	// Get converter
	converter, err := GetConverter("anchore-grype", "hdf")
	require.NoError(t, err, "Failed to get Anchore Grype converter")

	// Valid JSON but minimal Anchore Grype structure
	// The converter is lenient and will accept this, using defaults for missing fields
	minimalGrype := []byte(`{"descriptor": {"name": "grype"}, "source": {"target": {"userInput": "test"}}, "matches": []}`)
	output, err := converter.Convert(minimalGrype)

	// Should succeed with minimal structure
	assert.NoError(t, err, "Should handle minimal structure gracefully")
	assert.NotNil(t, output, "Output should not be nil")
	assert.Contains(t, string(output), "\"baselines\"")
}

// Helper function to get path to Anchore Grype fixture files.
// Navigates from cmd/hdf/cmd/ to converters/anchore-grype-to-hdf/fixtures/.
func anchoreGrypeFixturePath(t *testing.T, name string) string {
	t.Helper()

	// Get the current working directory
	cwd, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")

	// Navigate to the converters directory
	// From cmd/hdf/cmd, go up 3 levels to hdf-cli, then up 1 to hdf-libs,
	// then into hdf-converters/converters/anchore-grype-to-hdf/fixtures
	fixturePath := filepath.Join(cwd, "..", "..", "..", "..", "hdf-converters", "converters", "anchore-grype-to-hdf", "fixtures", name)

	// Clean the path
	fixturePath = filepath.Clean(fixturePath)

	return fixturePath
}
