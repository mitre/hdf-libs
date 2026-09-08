package hipcheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func countRequirements(t *testing.T, data []byte) (int, error) {
	t.Helper()
	result, err := ConvertHipcheckToHDF(data, "test")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n, nil
}

// One requirement per passing, failing, and errored analysis with no size limit, or one no-findings requirement when the report carries none.
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
		require.Equal(t, "Hipcheck analyses", unit)
		require.Equal(t, produced, expected, "relation broken for %s", filepath.Base(path))
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("   "), []byte("{}"), []byte("garbage"), []byte("{\"hipcheck_version\":\"3.0.0\"}"), []byte("{\"repo_name\":\"r\",\"passing\":[],\"failing\":[],\"errored\":[]}")} {
		produced, convErr := countRequirements(t, bad)
		expected, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
		if convErr == nil {
			require.Equal(t, produced, expected, "input %q: relation broken", string(bad))
		}
	}
}
