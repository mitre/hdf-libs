package semgrep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every fixture, including the no-findings and scan-errors shapes that add
// synthetic requirements: the expectation must land exactly on the output.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertSemgrepToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct semgrep rules plus the scan-status requirements", unit)
		n := 0
		for _, b := range result.Baselines {
			n += len(b.Requirements)
		}
		require.Equal(t, n, expected, "relation broken for %s", filepath.Base(path))
	}
}
