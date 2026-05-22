package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCKLConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("ckl", "hdf")
	require.NoError(t, err, "CKL converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "CKL to HDF", converter.Name())
}

func TestCKLConverter_Convert_Sample(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "ckl-to-hdf", "input/firefox-stig.ckl"))
	require.NoError(t, err, "Failed to read firefox-stig.ckl fixture")

	converter, err := GetConverter("ckl", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestCKLConverter_Convert_InvalidXML(t *testing.T) {
	converter, err := GetConverter("ckl", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid xml"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "ckl conversion failed")
}

func TestCKLConverter_Convert_EmptyInput(t *testing.T) {
	converter, err := GetConverter("ckl", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
