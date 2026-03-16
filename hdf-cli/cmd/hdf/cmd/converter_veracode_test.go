package cmd //nolint:dupl // thin CLI converter test — intentionally follows standard pattern

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVeracodeConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("veracode", "hdf")
	require.NoError(t, err, "Veracode converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "Veracode to HDF", converter.Name())
}

func TestVeracodeConverter_Convert_Sample(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "veracode-to-hdf", "input/veracode.xml"))
	require.NoError(t, err, "Failed to read veracode fixture")

	converter, err := GetConverter("veracode", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestVeracodeConverter_Convert_InvalidXML(t *testing.T) {
	converter, err := GetConverter("veracode", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid xml"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "veracode conversion failed")
}

func TestVeracodeConverter_Convert_EmptyInput(t *testing.T) {
	converter, err := GetConverter("veracode", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
