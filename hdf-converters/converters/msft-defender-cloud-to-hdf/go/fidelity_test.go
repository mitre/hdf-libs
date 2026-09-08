package msftdefendercloud

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

// Every fixture, including the clean subscription that synthesizes the
// no-findings requirement: the expectation is computed from the INPUT alone
// and must land exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertMsftDefenderCloudToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct Defender for Cloud assessment names", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// The sample carries one assessment per name, so its count equals the value
// array length; the relation is nonetheless distinct names, which the
// repeated-name input below pins.
func TestExpectedRequirementCount_GroupsAssessmentsByName(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "sample.json"))
	require.NoError(t, err)
	var raw defenderCloudInput
	require.NoError(t, json.Unmarshal(data, &raw))
	require.Equal(t, 6, len(raw.Value), "fixture drifted")

	expected, _, err := ExpectedRequirementCount(data)
	require.NoError(t, err)
	require.Equal(t, 6, expected)
	result, err := ConvertMsftDefenderCloudToHDF(data, "test")
	require.NoError(t, err)
	require.Equal(t, 6, totalRequirements(result))

	// The same assessment name over two resources is one requirement with two
	// results, in the API and in the relation.
	repeated := []byte(`{"value":[{"name":"a","properties":{}},{"name":"a","properties":{}},{"name":"b","properties":{}}]}`)
	expected, _, err = ExpectedRequirementCount(repeated)
	require.NoError(t, err)
	require.Equal(t, 2, expected)
	result, err = ConvertMsftDefenderCloudToHDF(repeated, "test")
	require.NoError(t, err)
	require.Equal(t, 2, totalRequirements(result))
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not json"), []byte("{}"), []byte(`{"value":null}`)} {
		_, convErr := ConvertMsftDefenderCloudToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
