package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCKLBConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("cklb", "hdf")
	require.NoError(t, err, "CKLB converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "CKLB to HDF", converter.Name())
}

func TestCKLBConverter_Convert_Sample(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "cklb-to-hdf", "input/firefox-stig.cklb"))
	require.NoError(t, err, "Failed to read firefox-stig.cklb fixture")

	converter, err := GetConverter("cklb", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestCKLBConverter_Convert_InvalidInput(t *testing.T) {
	converter, err := GetConverter("cklb", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "cklb conversion failed")
}

func TestCKLBConverter_Convert_EmptyInput(t *testing.T) {
	converter, err := GetConverter("cklb", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
