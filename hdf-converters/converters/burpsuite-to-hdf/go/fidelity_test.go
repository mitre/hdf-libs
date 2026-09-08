package burpsuite

import (
	"encoding/xml"
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

// Every fixture, including the empty export that synthesizes the no-findings
// requirement: the expectation is computed from the INPUT alone and must land
// exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.xml"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertBurpsuiteToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct Burp issue types", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// The real export carries 60 issues under 14 types: a count of issues would be
// wrong, distinct types is right. Pinning both numbers keeps a 1:1 relation
// from passing.
func TestExpectedRequirementCount_GroupsIssuesByType(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "zero.webappsecurity.com.xml"))
	require.NoError(t, err)
	var export BurpIssues
	require.NoError(t, xml.Unmarshal(data, &export))
	require.Equal(t, 60, len(export.Issues), "fixture drifted")

	expected, _, err := ExpectedRequirementCount(data)
	require.NoError(t, err)
	require.Equal(t, 14, expected)
	result, err := ConvertBurpsuiteToHDF(data, "test")
	require.NoError(t, err)
	require.Equal(t, 14, totalRequirements(result))
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not xml"), []byte("<issues/>")} {
		_, convErr := ConvertBurpsuiteToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
