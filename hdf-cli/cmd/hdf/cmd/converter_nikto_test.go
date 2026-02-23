package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ensureNiktoRegistered() {
	RegisterConverter("nikto", "hdf", &niktoConverter{})
}

func TestNiktoConverter_IsRegistered(t *testing.T) {
	ensureNiktoRegistered()

	converter, err := GetConverter("nikto", "hdf")
	require.NoError(t, err, "Nikto converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "Nikto to HDF", converter.Name())
}

func TestNiktoConverter_Convert_Minimal(t *testing.T) {
	ensureNiktoRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "nikto-to-hdf", "input/minimal.json"))
	require.NoError(t, err, "Failed to read minimal.json fixture")

	converter, err := GetConverter("nikto", "hdf")
	require.NoError(t, err, "Failed to get Nikto converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestNiktoConverter_Convert_InvalidJSON(t *testing.T) {
	ensureNiktoRegistered()

	converter, err := GetConverter("nikto", "hdf")
	require.NoError(t, err, "Failed to get Nikto converter")

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "nikto conversion failed")
}

func TestNiktoConverter_Convert_EmptyInput(t *testing.T) {
	ensureNiktoRegistered()

	converter, err := GetConverter("nikto", "hdf")
	require.NoError(t, err, "Failed to get Nikto converter")

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}
