package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureXccdfRegistered ensures the xccdf/arf converter is registered.
// Call this at the start of each test since some tests reset the global registry.
func ensureXccdfRegistered() {
	converter := &xccdfConverter{}
	RegisterConverter("xccdf", "hdf", converter)
	RegisterConverter("arf", "hdf", converter)
}

func TestXccdfConverter_IsRegistered(t *testing.T) {
	ensureXccdfRegistered()

	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err, "XCCDF converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "XCCDF/ARF to HDF", converter.Name())
}

func TestXccdfConverter_Convert_StigRhel7(t *testing.T) {
	ensureXccdfRegistered()

	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/stig-rhel7.xml"),
	)
	require.NoError(t, err, "Failed to read stig-rhel7.xml fixture")

	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err, "Failed to get XCCDF converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestXccdfConverter_Convert_Minimal(t *testing.T) {
	ensureXccdfRegistered()

	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/minimal.xml"),
	)
	require.NoError(t, err, "Failed to read minimal.xml fixture")

	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err, "Failed to get XCCDF converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestXccdfConverter_Convert_InvalidXML(t *testing.T) {
	ensureXccdfRegistered()

	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err, "Failed to get XCCDF converter")

	output, err := converter.Convert([]byte("not xml"))
	assert.Error(t, err, "Should fail on invalid XML")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "xccdf conversion failed")
}

// --- ARF alias tests ---

func TestArfConverter_IsRegistered(t *testing.T) {
	ensureXccdfRegistered()

	converter, err := GetConverter("arf", "hdf")
	require.NoError(t, err, "ARF converter should be registered as alias")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "XCCDF/ARF to HDF", converter.Name())
}

func TestArfConverter_Convert_Minimal(t *testing.T) {
	ensureXccdfRegistered()

	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/arf-minimal.xml"),
	)
	require.NoError(t, err, "Failed to read arf-minimal.xml fixture")

	converter, err := GetConverter("arf", "hdf")
	require.NoError(t, err, "Failed to get ARF converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}
