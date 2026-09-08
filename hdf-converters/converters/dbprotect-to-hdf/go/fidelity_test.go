package dbprotect

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

// Both report shapes (Check Results Details and Findings Detail): the
// expectation is computed from the INPUT alone and must land exactly on what
// the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.xml"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertDbprotectToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct DBProtect check ids", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// The check-results report carries 8 rows under 6 Check IDs: a count of rows
// would be wrong, distinct Check IDs is right. Pinning both numbers keeps a
// 1:1 relation from passing.
func TestExpectedRequirementCount_GroupsRowsByCheckID(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "sample-check-results.xml"))
	require.NoError(t, err)
	var ds Dataset
	require.NoError(t, xml.Unmarshal(data, &ds))
	require.Equal(t, 8, len(ds.Data.Rows), "fixture drifted")

	expected, _, err := ExpectedRequirementCount(data)
	require.NoError(t, err)
	require.Equal(t, 6, expected)
	result, err := ConvertDbprotectToHDF(data, "test")
	require.NoError(t, err)
	require.Equal(t, 6, totalRequirements(result))
}

// DBProtect synthesizes no placeholder: a dataset with no rows is rejected by
// both, so the expectation never claims a count the converter cannot produce.
func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not xml"), []byte("<dataset><metadata/><data/></dataset>")} {
		_, convErr := ConvertDbprotectToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
