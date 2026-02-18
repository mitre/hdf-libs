package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNessusConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Nessus converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "Nessus to HDF", converter.Name())
}

func TestNessusConverter_Convert_Minimal(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "nessus-to-hdf", "input/minimal.nessus"))
	require.NoError(t, err, "Failed to read minimal.nessus fixture")

	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Failed to get Nessus converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	s := string(output)
	assert.Contains(t, s, "\"baselines\"")
	assert.Contains(t, s, "\"targets\"")
	assert.Contains(t, s, "\"generator\"")
}

func TestNessusConverter_Convert_Compliance(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "nessus-to-hdf", "input/compliance.nessus"))
	require.NoError(t, err, "Failed to read compliance.nessus fixture")

	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Failed to get Nessus converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	s := string(output)
	assert.Contains(t, s, "\"baselines\"")
	assert.Contains(t, s, "DISA STIG")
}

func TestNessusConverter_Convert_InvalidXML(t *testing.T) {
	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Failed to get Nessus converter")

	output, err := converter.Convert([]byte("not valid xml"))
	assert.Error(t, err, "Should fail on invalid XML")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "nessus conversion failed")
}

func TestNessusConverter_Convert_EmptyInput(t *testing.T) {
	converter, err := GetConverter("nessus", "hdf")
	require.NoError(t, err, "Failed to get Nessus converter")

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}
