package snyk

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

// Every fixture, including the clean project that synthesizes the no-findings
// requirement: the expectation is computed from the INPUT alone and must land
// exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertSnykToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct Snyk vulnerability ids per project", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// Snyk repeats a vulnerability id once per dependency path: the goof project
// reports 56 entries under 27 ids. A count of entries would be wrong, distinct
// ids is right. Pinning both numbers keeps a 1:1 relation from passing.
func TestExpectedRequirementCount_GroupsVulnerabilitiesByID(t *testing.T) {
	cases := []struct {
		fixture  string
		vulns    int
		expected int
	}{
		{"nodejs-goof-local.json", 56, 27},
		{"nodejs-goof-remote.json", 23, 17},
		{"minimal.json", 9, 8},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", c.fixture))
		require.NoError(t, err)
		var report SnykReport
		require.NoError(t, json.Unmarshal(data, &report))
		require.Equal(t, c.vulns, len(report.Vulnerabilities), "fixture drifted: %s", c.fixture)

		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, c.expected, expected, c.fixture)
		result, err := ConvertSnykToHDF(data, "test")
		require.NoError(t, err)
		require.Equal(t, c.expected, totalRequirements(result), c.fixture)
	}
}

// An array of projects yields one baseline each; a clean project still counts
// its no-findings requirement, so the sum is per-project, not global.
func TestExpectedRequirementCount_SumsAcrossProjects(t *testing.T) {
	local, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "nodejs-goof-local.json"))
	require.NoError(t, err)
	empty, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "empty.json"))
	require.NoError(t, err)
	multi := []byte("[" + string(local) + "," + string(empty) + "]")

	expected, _, err := ExpectedRequirementCount(multi)
	require.NoError(t, err)
	require.Equal(t, 28, expected)
	result, err := ConvertSnykToHDF(multi, "test")
	require.NoError(t, err)
	require.Equal(t, 2, len(result.Baselines))
	require.Equal(t, 28, totalRequirements(result))
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not json"), []byte("{}"), []byte("[]"), []byte("null")} {
		_, convErr := ConvertSnykToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
