//nolint:dupl
package cmd

import (
	"os"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- xccdf-results (requires TestResult) ---

func TestXccdfResultsConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "xccdf-results",
		DisplayName:    "XCCDF Results to HDF",
		FixtureDir:     "xccdf-results-to-hdf",
		MinimalFixture: "input/minimal.xml",
		ErrPrefix:      "xccdf-results conversion failed",
		InvalidInput:   "not xml",
	})
}

func TestXccdfResultsConverter_StigRhel7(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/stig-rhel7.xml"),
	)
	require.NoError(t, err, "Failed to read stig-rhel7.xml fixture")

	converter, err := GetConverter("xccdf-results", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestXccdfResultsConverter_ErrorsOnBenchmark(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/benchmark-minimal-1.1.xml"),
	)
	require.NoError(t, err)

	converter, err := GetConverter("xccdf-results", "hdf")
	require.NoError(t, err)

	_, err = converter.Convert(inputData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no TestResult")
}

// --- xccdf-benchmark (requires no TestResult) ---

func TestXccdfBenchmarkConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("xccdf-benchmark", "hdf")
	require.NoError(t, err, "xccdf-benchmark converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "XCCDF Benchmark to HDF Baseline", converter.Name())
}

func TestXccdfBenchmarkConverter_Minimal11(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/benchmark-minimal-1.1.xml"),
	)
	require.NoError(t, err)

	converter, err := GetConverter("xccdf-benchmark", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	// Validate as HDF Baseline (not Results)
	result := validators.ValidateBaseline(output)
	assert.True(t, result.Valid,
		"Benchmark output must pass HDF baseline schema validation: %s", result.Error())
}

func TestXccdfBenchmarkConverter_Minimal12(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/benchmark-minimal-1.2.xml"),
	)
	require.NoError(t, err)

	converter, err := GetConverter("xccdf-benchmark", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	result := validators.ValidateBaseline(output)
	assert.True(t, result.Valid,
		"Benchmark output must pass HDF baseline schema validation: %s", result.Error())
}

func TestXccdfBenchmarkConverter_ErrorsOnResults(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/stig-rhel7.xml"),
	)
	require.NoError(t, err)

	converter, err := GetConverter("xccdf-benchmark", "hdf")
	require.NoError(t, err)

	_, err = converter.Convert(inputData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TestResult")
}

func TestXccdfBenchmarkConverter_ErrorsOnInvalidInput(t *testing.T) {
	converter, err := GetConverter("xccdf-benchmark", "hdf")
	require.NoError(t, err)

	_, err = converter.Convert([]byte("not xml"))
	assert.Error(t, err)
}

func TestXccdfBenchmarkConverter_ErrorsOnEmptyInput(t *testing.T) {
	converter, err := GetConverter("xccdf-benchmark", "hdf")
	require.NoError(t, err)

	_, err = converter.Convert([]byte{})
	assert.Error(t, err)
}

// --- xccdf (auto-detect) ---

func TestXccdfAutoDetectConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err, "xccdf converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "XCCDF to HDF (auto-detect)", converter.Name())
}

func TestXccdfAutoDetectConverter_BenchmarkToBaseline(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/benchmark-minimal-1.1.xml"),
	)
	require.NoError(t, err)

	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	// Auto-detect should produce baseline for benchmark input
	result := validators.ValidateBaseline(output)
	assert.True(t, result.Valid,
		"Auto-detect benchmark output must pass HDF baseline schema validation: %s", result.Error())
}

func TestXccdfAutoDetectConverter_ResultsToResults(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/stig-rhel7.xml"),
	)
	require.NoError(t, err)

	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestXccdfAutoDetectConverter_ArfToResults(t *testing.T) {
	inputData, err := os.ReadFile(
		converterFixturePath(t, "xccdf-results-to-hdf", "input/arf-minimal.xml"),
	)
	require.NoError(t, err)

	converter, err := GetConverter("xccdf", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

// --- arf (always results) ---

func TestArfConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("arf", "hdf")
	require.NoError(t, err, "ARF converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "ARF to HDF", converter.Name())
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
