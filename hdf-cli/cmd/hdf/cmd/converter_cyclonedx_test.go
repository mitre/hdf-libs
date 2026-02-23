//nolint:dupl // Converter test files are intentionally structural mirrors of each other.
package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureCycloneDXRegistered ensures the cyclonedx converter is registered.
func ensureCycloneDXRegistered() {
	RegisterConverter("cyclonedx", "hdf", &cyclonedxConverter{})
}

func TestCycloneDXConverter_IsRegistered(t *testing.T) {
	ensureCycloneDXRegistered()

	converter, err := GetConverter("cyclonedx", "hdf")
	require.NoError(t, err, "cyclonedx converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "CycloneDX to HDF", converter.Name())
}

func TestCycloneDXConverter_Convert_Minimal(t *testing.T) {
	ensureCycloneDXRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "cyclonedx-to-hdf", "input/minimal-vulns.json"))
	require.NoError(t, err, "failed to read minimal-vulns.json fixture")

	converter, err := GetConverter("cyclonedx", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestCycloneDXConverter_Convert_InvalidInput(t *testing.T) {
	ensureCycloneDXRegistered()

	converter, err := GetConverter("cyclonedx", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "cyclonedx conversion failed")
}

func TestCycloneDXConverter_Convert_EmptyInput(t *testing.T) {
	ensureCycloneDXRegistered()

	converter, err := GetConverter("cyclonedx", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
