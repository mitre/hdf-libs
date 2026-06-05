package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrufflehogConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "trufflehog",
		DisplayName:    "TruffleHog to HDF",
		FixtureDir:     "trufflehog-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "trufflehog conversion failed",
	})
}

func TestTrufflehogConverter_Convert_MultiDetector(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "trufflehog-to-hdf", "input/multi-detector.json"))
	require.NoError(t, err)

	converter, err := GetConverter("trufflehog", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestTrufflehogConverter_Convert_NDJSON(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "trufflehog-to-hdf", "input/ndjson-input.ndjson"))
	require.NoError(t, err)

	converter, err := GetConverter("trufflehog", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestTrufflehogConverter_Convert_EmptyArray(t *testing.T) {
	converter, err := GetConverter("trufflehog", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("[]"))
	require.NoError(t, err, "empty trufflehog input should produce a valid clean-scan HDF document, not an error")
	require.NotEmpty(t, output)
	assertHDFOutput(t, output)
	assert.Contains(t, string(output), "trufflehog-no-findings")
}
