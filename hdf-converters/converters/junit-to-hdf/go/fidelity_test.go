package junit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// One requirement per testcase across every suite, or one no-findings
// requirement when there are none — checked on every fixture, including the
// testsuite-less shape that once collapsed to a single requirement.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.xml"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertJUnitToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "JUnit testcases at every nesting depth", unit)
		n := 0
		for _, b := range result.Baselines {
			n += len(b.Requirements)
		}
		require.Equal(t, n, expected, "relation broken for %s", filepath.Base(path))
	}
}
