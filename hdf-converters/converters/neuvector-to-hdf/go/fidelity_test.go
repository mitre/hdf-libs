package neuvector

import (
	"encoding/json"
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

// Every fixture, including the clean image that synthesizes the no-findings
// requirement: the expectation is computed from the INPUT alone and must land
// exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertNeuVectorToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct NeuVector vulnerability ids", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// Both real scans carry exact duplicates of the name/package/version composite
// that the converter drops: a count of entries would be wrong, distinct ids is
// right. Pinning both numbers keeps a 1:1 relation from passing.
func TestExpectedRequirementCount_DropsDuplicateIDs(t *testing.T) {
	cases := []struct {
		fixture  string
		vulns    int
		expected int
	}{
		{"neuvector-mitre-heimdall.json", 192, 190},
		{"neuvector-mitre-heimdall2.json", 105, 104},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", c.fixture))
		require.NoError(t, err)
		var scan NeuVectorScan
		require.NoError(t, json.Unmarshal(data, &scan))
		require.Equal(t, c.vulns, len(scan.Report.Vulnerabilities), "fixture drifted: %s", c.fixture)

		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, c.expected, expected, c.fixture)
		result, err := ConvertNeuVectorToHDF(data, "test")
		require.NoError(t, err)
		require.Equal(t, c.expected, totalRequirements(result), c.fixture)
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not json"), []byte("{}"), []byte("[]")} {
		_, convErr := ConvertNeuVectorToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
