package cmd //nolint:dupl // thin CLI converter test — intentionally follows standard pattern

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBurpsuiteConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("burpsuite", "hdf")
	require.NoError(t, err, "BurpSuite converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "BurpSuite to HDF", converter.Name())
}

func TestBurpsuiteConverter_Convert_Sample(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "burpsuite-to-hdf", "input/zero.webappsecurity.com.xml"))
	require.NoError(t, err, "Failed to read burpsuite fixture")

	converter, err := GetConverter("burpsuite", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestBurpsuiteConverter_Convert_InvalidXML(t *testing.T) {
	converter, err := GetConverter("burpsuite", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid xml"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "burpsuite conversion failed")
}

func TestBurpsuiteConverter_Convert_EmptyInput(t *testing.T) {
	converter, err := GetConverter("burpsuite", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
