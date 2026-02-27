package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXccdfConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "xccdf",
		DisplayName:    "XCCDF/ARF to HDF",
		FixtureDir:     "xccdf-results-to-hdf",
		MinimalFixture: "input/minimal.xml",
		ErrPrefix:      "xccdf conversion failed",
		InvalidInput:   "not xml",
	})
}

func TestXccdfConverter_Convert_StigRhel7(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/stig-rhel7.xml"),
	)
	require.NoError(t, err, "Failed to read stig-rhel7.xml fixture")

	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

// --- ARF alias tests ---

func TestArfConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("arf", "hdf")
	require.NoError(t, err, "ARF converter should be registered as alias")
	assert.NotNil(t, converter)
	assert.Equal(t, "XCCDF/ARF to HDF", converter.Name())
}

func TestArfConverter_Convert_Minimal(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/arf-minimal.xml"),
	)
	require.NoError(t, err, "Failed to read arf-minimal.xml fixture")

	converter, err := GetConverter("arf", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}
