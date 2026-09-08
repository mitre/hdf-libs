package nikto_to_hdf

import (
	"encoding/json"
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

// Every fixture, including the clean host that synthesizes the no-findings
// requirement: the expectation is computed from the INPUT alone and must land
// exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertNiktoToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct Nikto ids", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// The real scan carries one entry per id, so its count equals the array
// length; the relation is nonetheless distinct ids, which the repeated-id
// input below pins.
func TestExpectedRequirementCount_GroupsVulnerabilitiesByID(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "zero.webappsecurity.json"))
	require.NoError(t, err)
	var report NiktoReport
	require.NoError(t, json.Unmarshal(data, &report))
	require.Equal(t, 14, len(report.Vulnerabilities), "fixture drifted")

	expected, _, err := ExpectedRequirementCount(data)
	require.NoError(t, err)
	require.Equal(t, 14, expected)
	result, err := ConvertNiktoToHDF(data, "test")
	require.NoError(t, err)
	require.Equal(t, 14, totalRequirements(result))

	repeated := []byte(`{"vulnerabilities":[{"id":"999","msg":"a","url":"/a"},{"id":"999","msg":"a","url":"/b"},{"id":"1","msg":"b"}]}`)
	expected, _, err = ExpectedRequirementCount(repeated)
	require.NoError(t, err)
	require.Equal(t, 2, expected)
	result, err = ConvertNiktoToHDF(repeated, "test")
	require.NoError(t, err)
	require.Equal(t, 2, totalRequirements(result))
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not json"), []byte("{}"), []byte("[]")} {
		_, convErr := ConvertNiktoToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
