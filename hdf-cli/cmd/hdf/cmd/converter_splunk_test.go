package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplunkConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "splunk",
		DisplayName:    "Splunk to HDF",
		FixtureDir:     "splunk-to-hdf",
		MinimalFixture: "input/splunk-minimal.json",
		ErrPrefix:      "splunk conversion failed",
	})
}

func TestSplunkConverter_Convert_Events(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "splunk-to-hdf", "input/splunk-events.json"))
	require.NoError(t, err, "Failed to read splunk-events.json fixture")

	converter, err := GetConverter("splunk", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}
