package sonarqube

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

// Every fixture, including the clean project that synthesizes the no-findings
// requirement: the expectation is computed from the INPUT alone and must land
// exactly on what the converter produces.
func TestExpectedRequirementCount_MatchesConversionForEveryFixture(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	for _, path := range inputs {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertSonarqubeToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		require.Equal(t, "distinct SonarQube rules per project", unit)
		require.Equal(t, totalRequirements(result), expected, "relation broken for %s", filepath.Base(path))
	}
}

// The real exports carry one issue per rule, so their counts equal the issues
// array length; the relation is nonetheless distinct (project, rule) pairs,
// which the repeated-rule input below pins.
func TestExpectedRequirementCount_GroupsIssuesByProjectAndRule(t *testing.T) {
	cases := []struct {
		fixture  string
		issues   int
		expected int
	}{
		{"sq26-owasp.json", 11, 11},
		{"mqr.json", 7, 7},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", c.fixture))
		require.NoError(t, err)
		var response IssuesResponse
		require.NoError(t, json.Unmarshal(data, &response))
		require.Equal(t, c.issues, len(response.Issues), "fixture drifted: %s", c.fixture)

		expected, _, err := ExpectedRequirementCount(data)
		require.NoError(t, err)
		require.Equal(t, c.expected, expected, c.fixture)
		result, err := ConvertSonarqubeToHDF(data, "test")
		require.NoError(t, err)
		require.Equal(t, c.expected, totalRequirements(result), c.fixture)
	}

	// The same rule in two projects is one requirement per project; the same
	// rule twice in one project is one requirement.
	repeated := []byte(`{"issues":[
		{"project":"p1","rule":"r1","component":"p1:a"},
		{"project":"p1","rule":"r1","component":"p1:b"},
		{"project":"p2","rule":"r1","component":"p2:a"}]}`)
	expected, _, err := ExpectedRequirementCount(repeated)
	require.NoError(t, err)
	require.Equal(t, 2, expected)
	result, err := ConvertSonarqubeToHDF(repeated, "test")
	require.NoError(t, err)
	require.Equal(t, 2, len(result.Baselines))
	require.Equal(t, 2, totalRequirements(result))
}

func TestExpectedRequirementCount_RejectsWhatTheConverterRejects(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte(""), []byte("not json"), []byte("{}"), []byte(`{"issues":null}`)} {
		_, convErr := ConvertSonarqubeToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "input %q: converter and expectation must agree on rejection", string(bad))
	}
}
