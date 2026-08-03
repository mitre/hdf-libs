package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHipcheckConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "hipcheck",
		DisplayName:    "Hipcheck to HDF",
		FixtureDir:     "hipcheck-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "hipcheck conversion failed",
	})
}

func TestHipcheckConverter_Convert_Real(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hipcheck-to-hdf", "input/real.json"))
	require.NoError(t, err)

	converter, err := GetConverter("hipcheck", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "conversion should succeed")
	require.NotEmpty(t, output)
	assertHDFOutput(t, output)
}

// A Hipcheck report auto-detects from its distinctive top-level shape
// (hipcheck_version + recommendation.risk_score), with no --from.
func TestHipcheckConverter_AutoDetect(t *testing.T) {
	fixture := converterFixturePath(t, "hipcheck-to-hdf", "input/real.json")
	stdout, stderr, err := executeCommand("convert", fixture)
	require.NoErrorf(t, err, "auto-detect of Hipcheck report should succeed (stderr: %s)", stderr)
	assert.Contains(t, stderr, "Detected: Hipcheck")
	assertHDFOutput(t, []byte(stdout))
}
