//nolint:dupl // CLI converter test wrappers are structurally similar by design
package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ensureZapRegistered() {
	RegisterConverter("zap", "hdf", &zapConverter{})
}

func TestZapConverter_IsRegistered(t *testing.T) {
	ensureZapRegistered()

	converter, err := GetConverter("zap", "hdf")
	require.NoError(t, err, "ZAP converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "OWASP ZAP to HDF", converter.Name())
}

func TestZapConverter_Convert_Minimal(t *testing.T) {
	ensureZapRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "zap-to-hdf", "input/minimal.json"))
	require.NoError(t, err, "Failed to read minimal.json fixture")

	converter, err := GetConverter("zap", "hdf")
	require.NoError(t, err, "Failed to get ZAP converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestZapConverter_Convert_InvalidJSON(t *testing.T) {
	ensureZapRegistered()

	converter, err := GetConverter("zap", "hdf")
	require.NoError(t, err, "Failed to get ZAP converter")

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "zap conversion failed")
}

func TestZapConverter_Convert_EmptyInput(t *testing.T) {
	ensureZapRegistered()

	converter, err := GetConverter("zap", "hdf")
	require.NoError(t, err, "Failed to get ZAP converter")

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}
