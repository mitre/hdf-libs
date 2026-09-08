package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func countRequirements(t *testing.T, data []byte) int {
	t.Helper()
	result, err := ConvertSarifToHDF(data, "test")
	require.NoError(t, err)
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n
}

// The declared relation must hold on every real fixture, not just the ones it
// was designed on: the expectation is computed from the INPUT alone and must
// land exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.sarif"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		expected, unit, err := ExpectedRequirementCount(data)
		require.NoError(t, err, path)
		require.Equal(t, "distinct SARIF rules", unit)
		require.Equal(t, countRequirements(t, data), expected, "relation broken for %s", filepath.Base(path))
	}
}

// Two real producers with opposite dedup profiles, both taken verbatim from
// mitre/hdf-libs CI run 34183673374 (2026-09-08): osv-scanner 2.5.1 (the
// scan-deps artifact) reports one result per rule, eslint 10.9.1 (the scan-ts
// artifact) reports 72 results under 5 rules. A count of results would be
// right for the first and wrong for the second; distinct rules is right for both.
func TestExpectedRequirementCount_RealProducers(t *testing.T) {
	cases := []struct {
		fixture  string
		results  int
		expected int
	}{
		{"osv-scanner-2.5.1.sarif", 5, 5},
		{"eslint-10.9.1.sarif", 72, 5},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", c.fixture))
		require.NoError(t, err)
		var file SarifFile
		require.NoError(t, json.Unmarshal(data, &file))
		require.Equal(t, c.results, len(file.Runs[0].Results), "fixture drifted: %s", c.fixture)
		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, c.expected, expected, c.fixture)
		require.Equal(t, c.expected, countRequirements(t, data), c.fixture)
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte("{}"), []byte(`{"runs":[]}`)} {
		_, convErr := ConvertSarifToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
