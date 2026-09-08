package cklb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func countRequirements(t *testing.T, data []byte) (int, error) {
	t.Helper()
	result, err := ConvertCKLBToHDF(data, "test")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n, nil
}

// The declared relation must hold on every real fixture: the expectation is
// computed from the INPUT alone and must land exactly on what the converter
// produces, and both must reject the same inputs.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.cklb"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		n, convErr := countRequirements(t, data)
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "CKLB rules", unit)
		require.Equal(t, n, expected, "relation broken for %s", filepath.Base(path))
	}
}

// Pinned vectors so a fixture drift or a grouping change is caught by name.
func TestExpectedRequirementCount_Vectors(t *testing.T) {
	cases := []struct {
		fixture  string
		expected int
	}{
		{"firefox-stig.cklb", 6},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", c.fixture))
		require.NoError(t, err)
		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, c.expected, expected, c.fixture)
		n, err := countRequirements(t, data)
		require.NoError(t, err)
		require.Equal(t, c.expected, n, c.fixture)
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("garbage"), []byte("{}"), []byte(`{"stigs":[]}`), []byte(`{"stigs":[{"rules":[]}]}`)} {
		_, convErr := ConvertCKLBToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
