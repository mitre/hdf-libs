//nolint:dupl // Converter test files are intentionally structural mirrors of each other.
package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureGosecRegistered ensures the gosec converter is registered.
// Call this at the start of each test since some tests reset the global registry.
func ensureGosecRegistered() {
	RegisterConverter("gosec", "hdf", &gosecConverter{})
}

func TestGosecConverter_IsRegistered(t *testing.T) {
	ensureGosecRegistered()

	converter, err := GetConverter("gosec", "hdf")
	require.NoError(t, err, "gosec converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "gosec to HDF", converter.Name())
}

func TestGosecConverter_Convert_Minimal(t *testing.T) {
	ensureGosecRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "gosec-to-hdf", "input/minimal.json"))
	require.NoError(t, err, "failed to read minimal.json fixture")

	converter, err := GetConverter("gosec", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestGosecConverter_Convert_InvalidInput(t *testing.T) {
	ensureGosecRegistered()

	converter, err := GetConverter("gosec", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "gosec conversion failed")
}

func TestGosecConverter_Convert_EmptyInput(t *testing.T) {
	ensureGosecRegistered()

	converter, err := GetConverter("gosec", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
