package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSConfigConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("aws-config", "hdf")
	require.NoError(t, err, "AWS Config converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "AWS Config to HDF", converter.Name())
}

func TestAWSConfigConverter_Convert_Minimal(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "aws-config-to-hdf", "input/minimal.json"))
	require.NoError(t, err, "Failed to read minimal.json fixture")

	converter, err := GetConverter("aws-config", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	assertHDFOutput(t, output)
}

func TestAWSConfigConverter_Convert_MultiRule(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "aws-config-to-hdf", "input/multi-rule.json"))
	require.NoError(t, err)

	converter, err := GetConverter("aws-config", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	assertHDFOutput(t, output)

	s := string(output)
	assert.Contains(t, s, "root-account-mfa-enabled")
	assert.Contains(t, s, "s3-bucket-server-side-encryption-enabled")
}

func TestAWSConfigConverter_Convert_InvalidInput(t *testing.T) {
	converter, err := GetConverter("aws-config", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "aws-config conversion failed")
}

func TestAWSConfigConverter_Convert_EmptyInput(t *testing.T) {
	converter, err := GetConverter("aws-config", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
