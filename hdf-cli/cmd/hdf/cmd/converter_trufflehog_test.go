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
		// TruffleHog emits no report on a clean scan; empty input is zero findings.
		AcceptsEmptyInput: true,
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

func TestTrufflehogConverter_AutoDetect_NDJSON(t *testing.T) {
	fixture := converterFixturePath(t, "trufflehog-to-hdf", "input/ndjson-input.ndjson")
	stdout, stderr, err := executeCommand("convert", fixture)
	require.NoErrorf(t, err, "auto-detect of trufflehog NDJSON should succeed (stderr: %s)", stderr)
	assert.Contains(t, stderr, "Detected: TruffleHog")
	assertHDFOutput(t, []byte(stdout))
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

// A clean TruffleHog scan reaches the CLI as a 0-byte file; with --from
// trufflehog it must convert to a zero-findings HDF document, not error.
func TestTrufflehogConverter_Convert_EmptyFile_ExplicitFrom(t *testing.T) {
	empty := converterFixturePath(t, "trufflehog-to-hdf", "input/empty-stdout.json")
	stdout, stderr, err := executeCommand("convert", "--from", "trufflehog", empty)
	require.NoErrorf(t, err, "empty file with --from trufflehog should succeed (stderr: %s)", stderr)
	assertHDFOutput(t, []byte(stdout))
	assert.Contains(t, stdout, "trufflehog-no-findings")
}

// Generalization guard: the empty-input carve-out is keyed on the converter's
// declared capability, not a hardcoded format name. A converter that does not
// opt in (nessus) must still reject the same 0-byte input, and empty input
// without --from must fail (no bytes to auto-detect).
func TestConvert_EmptyInput_RejectedForNonOptingConverters(t *testing.T) {
	empty := converterFixturePath(t, "trufflehog-to-hdf", "input/empty-stdout.json")

	t.Run("nessus rejects empty file", func(t *testing.T) {
		_, _, err := executeCommand("convert", "--from", "nessus", empty)
		require.Error(t, err, "nessus does not accept empty input")
	})
	t.Run("empty file without --from fails", func(t *testing.T) {
		_, _, err := executeCommand("convert", empty)
		require.Error(t, err, "empty input cannot be auto-detected")
	})
}
