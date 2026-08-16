package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrivyConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "trivy",
		DisplayName:    "Trivy to HDF",
		FixtureDir:     "trivy-to-hdf",
		MinimalFixture: "input/image-webgoat.json",
		ErrPrefix:      "trivy conversion failed",
	})
}

func TestTrivyConverter_AutoDetect(t *testing.T) {
	fixture := converterFixturePath(t, "trivy-to-hdf", "input/image-webgoat.json")
	stdout, stderr, err := executeCommand("convert", fixture)
	require.NoErrorf(t, err, "auto-detect of native Trivy JSON should succeed (stderr: %s)", stderr)
	assert.Contains(t, stderr, "Detected: Trivy")
	assertHDFOutput(t, []byte(stdout))
}

func TestTrivyConverter_EmptyScanSynthesizesPassed(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "trivy-to-hdf", "input/empty.json"))
	require.NoError(t, err)

	converter, err := GetConverter("trivy", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	assertHDFOutput(t, output)
	assert.Contains(t, string(output), "trivy-no-findings")
}

// --from trivy routes a non-native Trivy format (SARIF) to its converter.
func TestTrivyConverter_RoutesSARIF(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "sarif-to-hdf", "input/gosec.sarif"))
	require.NoError(t, err)

	converter, err := GetConverter("trivy", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "trivy converter should delegate SARIF input to the SARIF converter")
	assertHDFOutput(t, output)
}
