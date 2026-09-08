package zap_to_hdf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func countRequirements(t *testing.T, data []byte) (int, error) {
	t.Helper()
	result, err := ConvertZapToHDF(data, "test")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n, nil
}

// One requirement per site[*].alerts[] entry within the size limit (repeated pluginids are suffixed, never merged), one no-findings requirement per site with no alerts, and a single placeholder when site[] is empty; SARIF-shaped input follows the SARIF relation.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		produced, convErr := countRequirements(t, data)
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "ZAP alerts", unit)
		require.Equal(t, produced, expected, "relation broken for %s", filepath.Base(path))
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("{}"), []byte("garbage"), []byte("[]"), []byte("{\"site\":[]}"), []byte("{\"site\":[{\"@name\":\"a\",\"alerts\":[]}]}"), []byte("{\"version\":\"2.1.0\",\"runs\":[]}"), []byte("{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"ZAP\"}},\"results\":[]}]}")} {
		produced, convErr := countRequirements(t, bad)
		expected, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
		if convErr == nil {
			require.Equal(t, produced, expected, "input %q: relation broken", string(bad))
		}
	}
}
