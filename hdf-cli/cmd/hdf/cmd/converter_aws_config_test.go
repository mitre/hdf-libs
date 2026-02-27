package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSConfigConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "aws-config",
		DisplayName:    "AWS Config to HDF",
		FixtureDir:     "aws-config-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "aws-config conversion failed",
	})
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
