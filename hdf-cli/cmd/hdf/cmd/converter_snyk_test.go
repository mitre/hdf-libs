//nolint:dupl // Converter test files are intentionally structural mirrors of each other.
package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureSnykRegistered ensures the snyk converter is registered.
func ensureSnykRegistered() {
	RegisterConverter("snyk", "hdf", &snykConverter{})
}

func TestSnykConverter_IsRegistered(t *testing.T) {
	ensureSnykRegistered()

	converter, err := GetConverter("snyk", "hdf")
	require.NoError(t, err, "snyk converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "Snyk to HDF", converter.Name())
}

func TestSnykConverter_Convert_Minimal(t *testing.T) {
	ensureSnykRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "snyk-to-hdf", "input/minimal.json"))
	require.NoError(t, err, "failed to read minimal.json fixture")

	converter, err := GetConverter("snyk", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestSnykConverter_Convert_InvalidInput(t *testing.T) {
	ensureSnykRegistered()

	converter, err := GetConverter("snyk", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "snyk conversion failed")
}

func TestSnykConverter_Convert_EmptyInput(t *testing.T) {
	ensureSnykRegistered()

	converter, err := GetConverter("snyk", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
