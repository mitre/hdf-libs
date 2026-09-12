package legacyhdf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
)

func countRequirements(t *testing.T, data []byte) (int, error) {
	t.Helper()
	v1, err := ParseLegacyHDF(data)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range ConvertLegacyHDF(v1, "test").Baselines {
		n += len(b.Requirements)
	}
	return n, nil
}

// legacyInputs is every exec-json corpus the converter is tested on: the
// local fixture plus the shared hdf-fixtures scans (single profile, three-layer
// overlay, wrapper) whose control totals collapse under flattening.
func legacyInputs(t *testing.T) map[string][]byte {
	t.Helper()
	minimal, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "minimal.json"))
	require.NoError(t, err)
	return map[string][]byte{
		"minimal.json":             minimal,
		"ubi9-scan.json":           fixtures.Inspec.Ubi9Scan,
		"container-scan.json":      fixtures.Inspec.ContainerScan,
		"three-layer-overlay.json": fixtures.Inspec.ThreeLayerOverlay,
		"wrapper.json":             fixtures.Inspec.Wrapper,
	}
}

// The declared relation must hold on every corpus: the expectation is computed
// from the INPUT alone (profile identities and control ids through the same
// FlattenOverlays call) and must land exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	for name, data := range legacyInputs(t) {
		n, convErr := countRequirements(t, data)
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", name)
		if convErr != nil {
			continue
		}
		require.Equal(t, "InSpec controls after overlay flattening", unit)
		require.Equal(t, n, expected, "relation broken for %s", name)
	}
}

// Pinned vectors: raw control totals versus the flattened count, so a change
// in overlay merging is caught by name.
func TestExpectedRequirementCount_Vectors(t *testing.T) {
	inputs := legacyInputs(t)
	cases := []struct {
		fixture     string
		rawControls int
		expected    int
	}{
		{"minimal.json", 1, 1},
		{"ubi9-scan.json", 452, 452},
		{"three-layer-overlay.json", 741, 247},
		{"wrapper.json", 1067, 534},
	}
	for _, c := range cases {
		data := inputs[c.fixture]
		v1, err := ParseLegacyHDF(data)
		require.NoError(t, err)
		raw := 0
		for _, p := range v1.Profiles {
			raw += len(p.Controls)
		}
		require.Equal(t, c.rawControls, raw, "fixture drifted: %s", c.fixture)
		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, c.expected, expected, c.fixture)
		n, err := countRequirements(t, data)
		require.NoError(t, err)
		require.Equal(t, c.expected, n, c.fixture)
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("garbage"), []byte("{}"), []byte(`{"version":"4.0","profiles":[]}`), []byte(`{"version":"4.0","profiles":[],"platform":{"name":"x"}}`)} {
		_, convErr := countRequirements(t, bad)
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
