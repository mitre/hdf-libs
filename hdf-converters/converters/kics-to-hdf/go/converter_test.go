package kics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "1.0.0"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return b
}

// findingReqs returns requirements derived from actual findings, excluding the
// synthetic coverage and no-findings records.
func findingReqs(out *hdf.HDFResults) []hdf.EvaluatedRequirement {
	var reqs []hdf.EvaluatedRequirement
	for _, r := range out.Baselines[0].Requirements {
		if r.ID == "kics-scan-coverage" || r.ID == "kics-no-findings" {
			continue
		}
		reqs = append(reqs, r)
	}
	return reqs
}

func requirementByID(out *hdf.HDFResults, id string) *hdf.EvaluatedRequirement {
	for i := range out.Baselines[0].Requirements {
		if out.Baselines[0].Requirements[i].ID == id {
			return &out.Baselines[0].Requirements[i]
		}
	}
	return nil
}

func convert(t *testing.T, name string) *hdf.HDFResults {
	t.Helper()
	out, err := ConvertKicsToHDF(fixture(t, name), testVersion)
	require.NoError(t, err)
	require.NotNil(t, out)
	return out
}

// ---- Contract ----

func TestRejectsEmptyInput(t *testing.T) {
	_, err := ConvertKicsToHDF([]byte(""), testVersion)
	require.Error(t, err)
}

func TestRejectsInvalidJSON(t *testing.T) {
	_, err := ConvertKicsToHDF([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestRejectsNonKicsDocument(t *testing.T) {
	for _, in := range []string{
		`{"foo":1}`,
		`{"queries":[]}`,
		`{"kics_version":"v1"}`,
		// key present but wrong type: a truncated or jq-filtered report must
		// not silently convert to a clean no-findings document
		`{"kics_version":"v2.1.20","queries":null}`,
		`{"kics_version":"v2.1.20","queries":{}}`,
		`{"kics_version":5,"queries":[]}`,
		`{"kics_version":null,"queries":[]}`,
	} {
		_, err := ConvertKicsToHDF([]byte(in), testVersion)
		require.ErrorContains(t, err, "does not look like a KICS report", "input: %s", in)
	}
}

// Convert and auto-detect must agree: an input the fingerprint scores 0 must
// not convert, and every accepted fixture must fingerprint at full confidence.
func TestConvertAndDetectAgree(t *testing.T) {
	for _, in := range []string{
		`{"kics_version":"v2.1.20","queries":null}`,
		`{"kics_version":"v2.1.20","queries":{}}`,
		`{"kics_version":5,"queries":[]}`,
		`{"kics_version":null,"queries":[]}`,
	} {
		var obj map[string]any
		require.NoError(t, json.Unmarshal([]byte(in), &obj))
		assert.Equal(t, 0.0, fingerprintObject(obj), in)
		_, err := ConvertKicsToHDF([]byte(in), testVersion)
		require.Error(t, err, in)
	}

	for _, name := range []string{"findings.json", "minimal.json", "zero-findings.json"} {
		raw := fixture(t, name)
		var fobj map[string]any
		require.NoError(t, json.Unmarshal(raw, &fobj))
		assert.Equal(t, 1.0, fingerprintObject(fobj), name)
		_, err := ConvertKicsToHDF(raw, testVersion)
		require.NoError(t, err, name)
	}
}

func TestConvertsMinimalFixture(t *testing.T) {
	out := convert(t, "minimal.json")
	require.Len(t, out.Baselines, 1)
	assert.Equal(t, "KICS Scan", out.Baselines[0].Name)
	require.NotNil(t, out.Tool.Name)
	assert.Equal(t, "KICS", *out.Tool.Name)
}

// ---- Mapping behaviour ----

func TestOneRequirementPerQuery(t *testing.T) {
	out := convert(t, "findings.json")
	seen := map[string]bool{}
	for _, r := range findingReqs(out) {
		assert.False(t, seen[r.ID], "duplicate requirement id %s", r.ID)
		seen[r.ID] = true
	}
}

func TestSeverityMappingKeepsFiveLevels(t *testing.T) {
	assert.Equal(t, 0.9, impactFor("CRITICAL"))
	assert.Equal(t, 0.7, impactFor("HIGH"))
	assert.Equal(t, 0.5, impactFor("MEDIUM"))
	assert.Equal(t, 0.3, impactFor("LOW"))
	// canonical info tier: 0.0, like every other converter in the repo. The
	// effective-status layer treats impact-0 requirements as notApplicable, so
	// info-tier findings stay visible without entering the compliance ratio.
	assert.Equal(t, 0.0, impactFor("INFO"))
	assert.Equal(t, 0.0, impactFor("TRACE"))
	// unknown and absent both fall to moderate
	assert.Equal(t, defaultImpact, impactFor("NOVEL"))
	assert.Equal(t, defaultImpact, impactFor(""))
}

func TestAbsentSeverityGetsUnratedMarker(t *testing.T) {
	start := time.Now().UTC()
	unrated := buildRequirement(Query{QueryID: "q", Files: []File{{FileName: "a.tf"}}}, start)
	assert.Equal(t, shared.UnratedSeverityValue, unrated.Tags[shared.UnratedSeverityTag])

	// an unrecognized token is a rating we don't know, not an absent rating
	novel := buildRequirement(Query{QueryID: "q", Severity: "NOVEL", Files: []File{{FileName: "a.tf"}}}, start)
	assert.Nil(t, novel.Tags[shared.UnratedSeverityTag])

	rated := buildRequirement(Query{QueryID: "q", Severity: "HIGH", Files: []File{{FileName: "a.tf"}}}, start)
	assert.Nil(t, rated.Tags[shared.UnratedSeverityTag])
}

// Parity twin of the TS prototype-named-token test: both languages must treat
// "constructor" as an ordinary unknown token (default impact, fallback tier).
func TestPrototypeNamedTokensAreOrdinaryUnknowns(t *testing.T) {
	assert.Equal(t, defaultImpact, impactFor("constructor"))
	_, _, source := ResolveControls(Query{QueryID: "constructor"}, KicsMappingData)
	assert.Equal(t, nistMappingFallback, source)
}

func TestRecordsWhyTheNistTagIsWhatItIs(t *testing.T) {
	out := convert(t, "findings.json")
	counts := map[string]int{}
	for _, r := range findingReqs(out) {
		v, _ := r.Tags[nistMappingTag].(string)
		require.Contains(t, []string{nistMappingTable, nistMappingCWE, nistMappingFallback}, v)
		counts[v]++
	}
	// the fixture deliberately contains both resolved and unresolved CWEs
	assert.Greater(t, counts[nistMappingCWE], 0)
	assert.Greater(t, counts[nistMappingFallback], 0)
}

func TestUnresolvedCweStaysVisible(t *testing.T) {
	out := convert(t, "findings.json")
	for _, r := range findingReqs(out) {
		if r.Tags[nistMappingTag] == nistMappingFallback {
			assert.NotNil(t, r.Tags["cwe"], "an invisible unmapped CWE is a gap nobody can see")
		}
	}
}

func TestCarriesTheRemediationPairSarifDrops(t *testing.T) {
	out := convert(t, "findings.json")
	found := false
	for _, r := range findingReqs(out) {
		for _, res := range r.Results {
			if res.Message != nil && len(*res.Message) > 0 {
				found = true
			}
		}
	}
	assert.True(t, found)
	assert.Contains(t, evidenceFor(File{ExpectedValue: "x should be true", ActualValue: "x is null", IssueType: "MissingAttribute"}), "Expected:")
	assert.Contains(t, evidenceFor(File{ExpectedValue: "a", ActualValue: "b"}), "Actual:")
}

func TestTagsCarryKicsMetadata(t *testing.T) {
	out := convert(t, "findings.json")
	r := findingReqs(out)[0]
	for _, k := range []string{"platform", "category", "severity", "issueType", "resourceType"} {
		assert.NotNil(t, r.Tags[k], "missing tag %s", k)
	}
}

func TestEveryResultIsFailed(t *testing.T) {
	out := convert(t, "findings.json")
	for _, r := range findingReqs(out) {
		for _, res := range r.Results {
			assert.Equal(t, hdf.Failed, res.Status)
		}
	}
}

func TestZeroFindingsProducesPlaceholder(t *testing.T) {
	out := convert(t, "zero-findings.json")
	assert.Empty(t, findingReqs(out))
	ph := requirementByID(out, "kics-no-findings")
	require.NotNil(t, ph)
	assert.Equal(t, 0.0, ph.Impact)
}

// ---- Edge cases ----

func TestCweNormalization(t *testing.T) {
	assert.Equal(t, []string{"CWE-778"}, cweIdentifiers(Query{CWE: "778"}))
	assert.Equal(t, []string{"CWE-778"}, cweIdentifiers(Query{CWE: "CWE-778"}))
	assert.Nil(t, cweIdentifiers(Query{CWE: ""}))
	assert.Nil(t, cweIdentifiers(Query{CWE: "  "}))
	assert.Nil(t, cweIdentifiers(Query{CWE: "not-a-number"}))
}

func TestLocationRendering(t *testing.T) {
	assert.Equal(t, "File: unknown", locationFor(File{}))
	got := locationFor(File{FileName: "main.tf", Line: 4, ResourceType: "aws_s3_bucket", ResourceName: "unknown", SearchKey: "k"})
	assert.Contains(t, got, "File: main.tf")
	assert.Contains(t, got, "Line: 4")
	assert.Contains(t, got, "Resource type: aws_s3_bucket")
	assert.NotContains(t, got, "Resource: unknown", "the literal placeholder should not be rendered")
	assert.Contains(t, got, "Key: k")
}

func TestQueriesWithoutOccurrencesAreSkipped(t *testing.T) {
	in := []byte(`{"kics_version":"v1","files_scanned":3,"queries":[{"query_id":"a","files":[]}]}`)
	out, err := ConvertKicsToHDF(in, testVersion)
	require.NoError(t, err)
	assert.Empty(t, findingReqs(out))
	assert.NotNil(t, requirementByID(out, "kics-no-findings"))
}

func TestFallsBackToQueryNameWhenIdMissing(t *testing.T) {
	q := Query{QueryName: "Some Check", Files: []File{{FileName: "a.tf"}}}
	r := buildRequirement(q, time.Now().UTC())
	assert.Equal(t, "Some Check", r.ID)
	assert.Equal(t, "Some Check", *r.Title)
}

func TestIdentityFallbacksWhenBothMissing(t *testing.T) {
	r := buildRequirement(Query{Files: []File{{FileName: "a.tf"}}}, time.Now().UTC())
	assert.Equal(t, "unknown", r.ID)
	assert.Equal(t, "Unnamed KICS query", *r.Title)
}

func TestRiskScoreTagFormatting(t *testing.T) {
	// strings pass through untouched
	tags, _ := tagsFor(Query{RiskScore: "7.1"})
	assert.Equal(t, "7.1", tags["riskScore"])
	// numbers format without exponent notation, matching TS String() across
	// KICS's realistic 0-10 risk_score range (and well beyond)
	tags, _ = tagsFor(Query{RiskScore: float64(1000000)})
	assert.Equal(t, "1000000", tags["riskScore"])
	tags, _ = tagsFor(Query{RiskScore: float64(8.6)})
	assert.Equal(t, "8.6", tags["riskScore"])
	// JSON null (key present, score not computed) omits the tag
	tags, _ = tagsFor(Query{RiskScore: nil})
	assert.Nil(t, tags["riskScore"])
}

func TestLocationCarriesSimilarityID(t *testing.T) {
	got := locationFor(File{FileName: "a.tf", SimilarityID: "4efca9c9"})
	assert.Contains(t, got, "Similarity ID: 4efca9c9")
	assert.NotContains(t, locationFor(File{FileName: "a.tf"}), "Similarity ID")
}

func TestTagsCarryQueryURL(t *testing.T) {
	tags, _ := tagsFor(Query{QueryURL: "https://example.com/docs"})
	assert.Equal(t, "https://example.com/docs", tags["queryUrl"])
	tags, _ = tagsFor(Query{})
	assert.Nil(t, tags["queryUrl"])
}

func TestDistinctDropsBlanksAndDuplicates(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, distinct([]string{"a", "", "a", "b", ""}))
	assert.Nil(t, distinct([]string{"", ""}))
}

// ---- Golden snapshots (TS<->Go parity) ----

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "kics-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertKicsToHDF(input, testVersion)
	}, "*")
}

// ---- Control resolution precedence ----

// The shipped table is intentionally empty until adjudication completes, so the
// table tier is exercised with a stub rather than by shipping unreviewed rows.
var stubTable = map[string]MappingEntry{
	"query-in-table": {CCI: []string{"CCI-000366"}, NIST: []string{"CM-6 b"}},
	"empty-entry":    {CCI: nil, NIST: nil},
}

func TestResolvePrefersTheReviewedTable(t *testing.T) {
	nist, ccis, source := ResolveControls(Query{QueryID: "query-in-table", CWE: "311"}, stubTable)
	assert.Equal(t, []string{"CM-6 b"}, nist)
	assert.Equal(t, []string{"CCI-000366"}, ccis)
	assert.Equal(t, nistMappingTable, source)
}

func TestResolveFallsBackToCwe(t *testing.T) {
	nist, _, source := ResolveControls(Query{QueryID: "absent", CWE: "311"}, stubTable)
	assert.Equal(t, nistMappingCWE, source)
	assert.NotEmpty(t, nist)
	assert.NotEqual(t, shared.DefaultStaticAnalysisNIST, nist)
	// shared.MapCWEToNIST sorts; TS mapCWEToNIST does too. Order is parity.
	assert.True(t, sort.StringsAreSorted(nist), "CWE-derived controls must be sorted: %v", nist)
}

func TestResolveFallsBackToDefaultsWhenCweUnmapped(t *testing.T) {
	// CWE-778 is one of the 72 KICS uses that the CWE table lacks
	nist, ccis, source := ResolveControls(Query{QueryID: "absent", CWE: "778"}, stubTable)
	assert.Equal(t, nistMappingFallback, source)
	assert.Equal(t, shared.DefaultStaticAnalysisNIST, nist)
	assert.NotEmpty(t, ccis)
}

func TestResolveFallsBackWhenNoCwe(t *testing.T) {
	_, _, source := ResolveControls(Query{QueryID: "absent"}, stubTable)
	assert.Equal(t, nistMappingFallback, source)
}

func TestResolveIgnoresTableEntryWithNoControls(t *testing.T) {
	_, _, source := ResolveControls(Query{QueryID: "empty-entry", CWE: "311"}, stubTable)
	assert.Equal(t, nistMappingCWE, source)
}

// ---- Scan coverage ----

func TestCoverageRequirementRecordsTheDenominator(t *testing.T) {
	out := convert(t, "findings.json")
	cov := requirementByID(out, "kics-scan-coverage")
	require.NotNil(t, cov)
	assert.Greater(t, cov.Tags["queriesExecuted"], cov.Tags["queriesWithFindings"])
	assert.Equal(t, 0.0, cov.Impact)
	// notApplicable matches what the effective-status layer derives for an
	// impact-0 requirement, and it is the one status the compliance rollup
	// excludes. Passed would export to CKL as NotAFinding and count as a free
	// pass in raw status rollups.
	assert.Equal(t, hdf.NotApplicable, cov.Results[0].Status)
	assert.Contains(t, cov.Results[0].CodeDesc, "violations only")
	assert.Contains(t, cov.Results[0].CodeDesc, "should not be read as a pass rate")
}

func TestCoverageRequirementPresentOnZeroFindings(t *testing.T) {
	out := convert(t, "zero-findings.json")
	assert.NotNil(t, requirementByID(out, "kics-scan-coverage"))
}
