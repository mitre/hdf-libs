package trivy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func countRequirements(t *testing.T, data []byte) (int, error) {
	t.Helper()
	result, err := ConvertTrivyToHDF(data, "test")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n, nil
}

// Native Trivy JSON: one requirement per entry of every Results[*] finding array (vulnerabilities, misconfigurations, secrets, licenses), or one no-findings requirement when there are none.
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
		require.Equal(t, "trivy findings", unit)
		require.Equal(t, produced, expected, "relation broken for %s", filepath.Base(path))
	}
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("   "), []byte("{}"), []byte("garbage"), []byte("[]"), []byte("{\"SchemaVersion\":2,\"ArtifactName\":\"a\",\"ArtifactType\":\"t\"}"), []byte("{\"SchemaVersion\":2,\"ArtifactName\":\"a\",\"ArtifactType\":\"t\",\"Results\":[{\"Target\":\"x\",\"Vulnerabilities\":[{\"VulnerabilityID\":\"CVE-2021-44228\"}],\"Secrets\":[{\"RuleID\":\"aws\"}]}]}")} {
		produced, convErr := countRequirements(t, bad)
		expected, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
		if convErr == nil {
			require.Equal(t, produced, expected, "input %q: relation broken", string(bad))
		}
	}
}

// Trivy's other output formats route to sibling converters; the expectation
// must route the same way and land on what that converter produces.
func TestExpectedRequirementCount_DelegatedShapesFollowTheirConverter(t *testing.T) {
	cases := []struct{ shape, fixture string }{
		{"cyclonedx", filepath.Join("..", "..", "cyclonedx-to-hdf", "fixtures", "input", "minimal-vulns.json")},
		{"sarif", filepath.Join("..", "..", "sarif-to-hdf", "fixtures", "input", "grype.sarif")},
		{"asff", filepath.Join("..", "..", "asff-to-hdf", "fixtures", "input", "trivy_sample.json")},
		{"gitlab", filepath.Join("..", "..", "gitlab-to-hdf", "fixtures", "input", "multi-vuln.json")},
	}
	for _, c := range cases {
		data, err := os.ReadFile(c.fixture)
		require.NoError(t, err, c.shape)
		produced, convErr := countRequirements(t, data)
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", c.shape)
		if convErr != nil {
			continue
		}
		require.NotEqual(t, "trivy findings", unit, "%s: a delegated shape must carry the delegate's unit", c.shape)
		require.Equal(t, produced, expected, "relation broken for delegated shape %s", c.shape)
	}
}
