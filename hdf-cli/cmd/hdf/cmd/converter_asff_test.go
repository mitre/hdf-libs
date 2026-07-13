package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAsffConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "asff",
		DisplayName:    "AWS Security Finding Format to HDF",
		FixtureDir:     "asff-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "asff conversion failed",
	})
}

func TestAsffConverter_SecurityHubSample_MultiBaseline(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "asff-to-hdf", "input/securityhub_sample.json"))
	require.NoError(t, err)

	converter, err := GetConverter("asff", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "conversion should succeed")
	assertHDFOutput(t, output)

	// Two Security Hub standards in the sample → two baselines in one document.
	assert.Contains(t, string(output), "CIS AWS Foundations Benchmark")
	assert.Contains(t, string(output), "AWS Foundational Security Best Practices")
}

func TestAsffConverter_AutoDetect(t *testing.T) {
	fixture := converterFixturePath(t, "asff-to-hdf", "input/securityhub_sample.json")
	stdout, stderr, err := executeCommand("convert", fixture)
	require.NoErrorf(t, err, "auto-detect of asff should succeed (stderr: %s)", stderr)
	assert.Contains(t, stderr, "Detected: AWS Security Finding Format")
	assertHDFOutput(t, []byte(stdout))
}

func TestAsffConverter_Convert_EmptyFindings(t *testing.T) {
	converter, err := GetConverter("asff", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(`{"Findings":[]}`))
	require.NoError(t, err, "empty ASFF input should produce a valid clean-scan HDF document, not an error")
	require.NotEmpty(t, output)
	assertHDFOutput(t, output)
	assert.Contains(t, string(output), "asff-no-findings")
}

func TestAsffConverter_Prowler_Trivy(t *testing.T) {
	for _, fx := range []string{"prowler_sample.json", "trivy_sample.json"} {
		t.Run(fx, func(t *testing.T) {
			inputData, err := os.ReadFile(converterFixturePath(t, "asff-to-hdf", "input/"+fx))
			require.NoError(t, err)
			converter, err := GetConverter("asff", "hdf")
			require.NoError(t, err)
			output, err := converter.Convert(inputData)
			require.NoError(t, err, "conversion should succeed")
			assertHDFOutput(t, output)
		})
	}
}

func TestAsffConverter_AutoDetect_NDJSON(t *testing.T) {
	fixture := converterFixturePath(t, "asff-to-hdf", "input/prowler_sample.ndjson")
	stdout, stderr, err := executeCommand("convert", fixture)
	require.NoErrorf(t, err, "auto-detect of Prowler NDJSON should succeed (stderr: %s)", stderr)
	assert.Contains(t, stderr, "Detected: AWS Security Finding Format")
	assertHDFOutput(t, []byte(stdout))
}
