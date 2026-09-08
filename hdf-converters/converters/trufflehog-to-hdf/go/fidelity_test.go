package trufflehog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func totalRequirements(result *hdf.HDFResults) int {
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n
}

// Every fixture across the three accepted shapes (array, single object,
// NDJSON) plus the 0-byte clean-scan stdout: the expectation is computed from
// the INPUT alone and must land exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertTrufflehogToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct TruffleHog detector/decoder pairs", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// Both multi-finding fixtures carry 3 findings under 2 detector/decoder pairs:
// a count of findings would be wrong, distinct pairs is right. Pinning both
// numbers keeps a 1:1 relation from passing.
func TestExpectedRequirementCount_GroupsFindingsByDetectorAndDecoder(t *testing.T) {
	for _, fixture := range []string{"multi-detector.json", "ndjson-input.ndjson"} {
		data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", fixture))
		require.NoError(t, err)
		findings, err := parseFindings(data)
		require.NoError(t, err)
		require.Equal(t, 3, len(findings), "fixture drifted: %s", fixture)

		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, 2, expected, fixture)
		result, err := ConvertTrufflehogToHDF(data, "test")
		require.NoError(t, err)
		require.Equal(t, 2, totalRequirements(result), fixture)
	}
}

// The converter is registered WithEmptyInputOK: a clean scan's empty stdout is
// one no-findings requirement, so the expectation must say 1, not reject.
func TestExpectedRequirementCount_EmptyInputIsACleanScan(t *testing.T) {
	for _, empty := range [][]byte{nil, []byte(""), []byte(" \n")} {
		expected, _, err := ExpectedRequirementCount(empty)
		require.NoError(t, err)
		require.Equal(t, 1, expected)
		result, err := ConvertTrufflehogToHDF(empty, "test")
		require.NoError(t, err)
		require.Equal(t, 1, totalRequirements(result))
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{[]byte("not json"), []byte("{}"), []byte("[]"), []byte("{\"a\":1}\nnot json")} {
		_, convErr := ConvertTrufflehogToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
