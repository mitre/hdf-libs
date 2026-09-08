package cyclonedxvex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func countOverrides(t *testing.T, data []byte) (int, error) {
	t.Helper()
	result, err := ConvertCycloneDXVEXToHDF(data, "test")
	if err != nil {
		return 0, err
	}
	return len(result.Overrides), nil
}

// The declared relation must hold on every real fixture: the expectation is
// computed from the INPUT alone and must land exactly on what the converter
// produces, and both must reject the same inputs.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		n, convErr := countOverrides(t, data)
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "CycloneDX vulnerabilities with an actionable VEX analysis state", unit)
		require.Equal(t, n, expected, "relation broken for %s", filepath.Base(path))
	}
}

// Pinned vectors so a fixture drift or a grouping change is caught by name.
func TestExpectedRequirementCount_Vectors(t *testing.T) {
	cases := []struct {
		fixture  string
		expected int
	}{
		{"case12-vex-multi-vuln.json", 2},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", c.fixture))
		require.NoError(t, err)
		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, c.expected, expected, c.fixture)
		n, err := countOverrides(t, data)
		require.NoError(t, err)
		require.Equal(t, c.expected, n, c.fixture)
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("garbage"), []byte("{}"), []byte(`{"bomFormat":"CycloneDX","vulnerabilities":[]}`)} {
		_, convErr := ConvertCycloneDXVEXToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}

// A document whose statements are all informational yields no override; the
// conversion refuses it and the expectation must refuse it too, not report 0.
func TestExpectedRequirementCount_ZeroOverridesIsAnError(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "case1-vex-affected.json"))
	require.NoError(t, err)
	_, convErr := ConvertCycloneDXVEXToHDF(data, "test")
	require.Error(t, convErr)
	_, _, expErr := ExpectedRequirementCount(data)
	require.Error(t, expErr)
	require.Equal(t, convErr.Error(), expErr.Error())
}
