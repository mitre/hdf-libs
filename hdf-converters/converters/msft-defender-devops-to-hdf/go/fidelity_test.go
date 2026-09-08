package msftdefenderdevops

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

// Every fixture, including runs with no results that get a no-findings
// requirement: the expectation is computed from the INPUT alone and must land
// exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.sarif"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertMsftDefenderDevopsToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct SARIF rules", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// The real MSDO export bundles 7 scanner runs: four are empty (one no-findings
// requirement each), the rest report 253 results under 61 rules. A count of
// results or of runs would both be wrong; per-run distinct rules plus the
// placeholders is right. Pinning the numbers keeps a 1:1 relation from passing.
func TestExpectedRequirementCount_SumsRulesAcrossRuns(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "sda.sarif"))
	require.NoError(t, err)
	var raw msdoSarif
	require.NoError(t, json.Unmarshal(data, &raw))
	require.Equal(t, 7, len(raw.Runs), "fixture drifted")
	results := 0
	for _, run := range raw.Runs {
		results += len(run.Results)
	}
	require.Equal(t, 253, results, "fixture drifted")

	expected, _, err := ExpectedRequirementCount(data)
	require.NoError(t, err)
	require.Equal(t, 65, expected)
	result, err := ConvertMsftDefenderDevopsToHDF(data, "test")
	require.NoError(t, err)
	require.Equal(t, 65, totalRequirements(result))
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not json"), []byte("{}"), []byte(`{"runs":[]}`)} {
		_, convErr := ConvertMsftDefenderDevopsToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
