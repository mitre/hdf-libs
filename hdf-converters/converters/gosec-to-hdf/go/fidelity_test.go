package gosec

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

// Every fixture, including the clean report that synthesizes the no-findings
// requirement: the expectation is computed from the INPUT alone and must land
// exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertGosecToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct gosec rules", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// Two real scans with heavy rule repetition: go-ethereum reports 173 issues
// under 5 rules. A count of issues would be wrong, distinct rules is right.
// Pinning both numbers keeps a 1:1 relation from passing.
func TestExpectedRequirementCount_GroupsIssuesByRule(t *testing.T) {
	cases := []struct {
		fixture  string
		issues   int
		expected int
	}{
		{"ethereum.json", 173, 5},
		{"real.json", 7, 3},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", c.fixture))
		require.NoError(t, err)
		var report GosecReport
		require.NoError(t, json.Unmarshal(data, &report))
		require.Equal(t, c.issues, len(report.Issues), "fixture drifted: %s", c.fixture)

		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, c.expected, expected, c.fixture)
		result, err := ConvertGosecToHDF(data, "test")
		require.NoError(t, err)
		require.Equal(t, c.expected, totalRequirements(result), c.fixture)
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not json"), []byte("{}"), []byte("[]")} {
		_, convErr := ConvertGosecToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
