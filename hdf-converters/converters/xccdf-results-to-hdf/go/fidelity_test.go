package xccdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func fixtureInputs(t *testing.T) []string {
	t.Helper()
	inputs, err := filepath.Glob(filepath.Join("..", "fixtures", "input", "*.xml"))
	require.NoError(t, err)
	require.NotEmpty(t, inputs)
	return inputs
}

func countEvaluated(result *hdf.HDFResults) int {
	n := 0
	for _, b := range result.Baselines {
		n += len(b.Requirements)
	}
	return n
}

// The results relation (xccdf-results and arf): one requirement per
// rule-result of every TestResult, or one no-findings requirement per
// TestResult without any. Benchmarks without a TestResult are rejected by
// both the converter and the expectation.
func TestExpectedRequirementCount_MatchesResultsConversionForEveryFixture(t *testing.T) {
	accepted := 0
	for _, path := range fixtureInputs(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertXccdfResultsToHDF(data, "test")
		expected, unit, expErr := ExpectedRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		accepted++
		require.Equal(t, "XCCDF rule-results", unit)
		require.Equal(t, countEvaluated(result), expected, "relation broken for %s", filepath.Base(path))
	}
	require.Positive(t, accepted, "no results-shaped fixture was exercised")
}

// The benchmark relation (xccdf-benchmark): one requirement per Rule with an
// id at any depth. The produced document is an HDF baseline whose
// requirements sit at the top level rather than under baselines[].
func TestExpectedBenchmarkRequirementCount_MatchesBenchmarkConversionForEveryFixture(t *testing.T) {
	accepted := 0
	for _, path := range fixtureInputs(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		result, convErr := ConvertXccdfBenchmarkToHDF(data, "test")
		expected, unit, expErr := ExpectedBenchmarkRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		accepted++
		require.Equal(t, "XCCDF rules", unit)
		require.Equal(t, len(result.Requirements), expected, "relation broken for %s", filepath.Base(path))
	}
	require.Positive(t, accepted, "no benchmark-shaped fixture was exercised")
}

// The auto-detect relation (xccdf) must follow the same root-shape dispatch
// as ConvertXccdfToHDF and count the document it actually produced.
func TestExpectedAutoDetectRequirementCount_MatchesAutoDetectForEveryFixture(t *testing.T) {
	kinds := map[string]int{}
	for _, path := range fixtureInputs(t) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		output, kind, convErr := ConvertXccdfToHDF(data, "test")
		expected, unit, expErr := ExpectedAutoDetectRequirementCount(data)
		require.Equal(t, convErr != nil, expErr != nil, "%s: converter and expectation must agree on rejection", path)
		if convErr != nil {
			continue
		}
		kinds[kind]++
		var produced int
		switch kind {
		case "results":
			var doc hdf.HDFResults
			require.NoError(t, json.Unmarshal(output, &doc))
			produced = countEvaluated(&doc)
			require.Equal(t, "XCCDF rule-results", unit)
		case "baseline":
			var doc hdf.HDFBaseline
			require.NoError(t, json.Unmarshal(output, &doc))
			produced = len(doc.Requirements)
			require.Equal(t, "XCCDF rules", unit)
		default:
			t.Fatalf("%s: unexpected output kind %q", path, kind)
		}
		require.Equal(t, produced, expected, "relation broken for %s", filepath.Base(path))
	}
	require.Positive(t, kinds["results"], "no results-shaped fixture was exercised")
	require.Positive(t, kinds["baseline"], "no benchmark-shaped fixture was exercised")
}

func TestExpectedRequirementCounts_RejectWhatTheConvertersReject(t *testing.T) {
	const benchmarkOnly = `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b"><Group id="g"><Rule id="r1"/><Rule id=""/></Group><Rule id="r2"/></Benchmark>`
	const emptyArf = `<asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"/>`
	inputs := [][]byte{nil, []byte(""), []byte("garbage"), []byte("<other/>"), []byte(benchmarkOnly), []byte(emptyArf)}
	for _, bad := range inputs {
		_, convErr := ConvertXccdfResultsToHDF(bad, "test")
		_, _, expErr := ExpectedRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "results relation, input %q", string(bad))

		baseline, convErr := ConvertXccdfBenchmarkToHDF(bad, "test")
		expected, _, expErr := ExpectedBenchmarkRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "benchmark relation, input %q", string(bad))
		if convErr == nil {
			require.Equal(t, len(baseline.Requirements), expected, "benchmark relation, input %q", string(bad))
		}

		_, _, convErr = ConvertXccdfToHDF(bad, "test")
		_, _, expErr = ExpectedAutoDetectRequirementCount(bad)
		require.Equal(t, convErr != nil, expErr != nil, "auto-detect relation, input %q", string(bad))
	}
}
