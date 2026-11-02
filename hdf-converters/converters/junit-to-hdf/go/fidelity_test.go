package junit

import (
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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

// The granularity model: a <testcase> is the requirement and a <testsuite> is a
// grouping, never the unit that decides pass or fail. Each requirement carries
// exactly one result and none is named for a suite. A suite-shaped requirement
// holding its cases as results would roll a mostly-passing suite up to failed
// under the worst-wins ladder and erase every pass from the compliance score.
func TestGranularity_TestcaseIsTheRequirement(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "testsuites-mixed.xml"), "test")
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 5, "five testcases across two suites")

	statuses := map[string]hdf.ResultStatus{}
	for _, r := range reqs {
		require.Len(t, r.Results, 1, "%s: one testcase, one verdict", r.ID)
		for _, suite := range []string{"MathTest", "StringTest"} {
			require.NotEqual(t, suite, r.ID, "a suite is not a requirement")
			require.NotEqual(t, suite, *r.Title, "a suite is not a requirement")
		}
		statuses[r.ID] = r.Results[0].Status
	}
	require.Equal(t, map[string]hdf.ResultStatus{
		"com.example.math.MathTest.testAddition":       hdf.Passed,
		"com.example.math.MathTest.testDivisionByZero": hdf.Failed,
		"com.example.math.MathTest.testSquareRoot":     hdf.NotReviewed,
		"com.example.string.StringTest.testConcat":     hdf.Passed,
		"com.example.string.StringTest.testParseInt":   hdf.Error,
	}, statuses, "each case keeps its own verdict; nothing is rolled up by suite")
}

// A Surefire flaky case — failed attempts, then a pass — converts to one passed
// result. The case's verdict is the one Surefire recorded; the retries are not
// separate results for the worst-wins ladder to turn into a failure.
func TestGranularity_FlakyPassIsOnePassedResult(t *testing.T) {
	result, err := ConvertJUnitToHDF(loadFixture(t, "surefire-flaky.xml"), "test")
	require.NoError(t, err)
	var flaky *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "org.acme.FlakyTest.testFlaky" {
			flaky = &result.Baselines[0].Requirements[i]
		}
	}
	require.NotNil(t, flaky)
	require.Len(t, flaky.Results, 1)
	require.Equal(t, hdf.Passed, flaky.Results[0].Status)
}
