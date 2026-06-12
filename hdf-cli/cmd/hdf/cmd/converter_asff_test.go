package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestASFFConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "asff",
		DisplayName:    "ASFF (AWS Security Finding Format) to HDF",
		FixtureDir:     "asff-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "asff conversion failed",
	})
}

func TestASFFConverter_SecurityHubProductName(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "asff-to-hdf", "input/securityhub.json"))
	require.NoError(t, err)

	converter, err := GetConverter("asff", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	assertHDFOutput(t, output)

	// SecurityHub case derives the baseline title from StandardsControlArn.
	s := string(output)
	assert.Contains(t, s, "v1.2.0", "SecurityHub case must put standard version into the baseline title")
}
