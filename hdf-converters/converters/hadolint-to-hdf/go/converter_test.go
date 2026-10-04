package hadolint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Matches the TypeScript converter's default so both languages generate and
// assert the same goldens.
const testVersion = "1.0.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func convertFixture(t *testing.T, name string) *hdf.HDFResults {
	t.Helper()
	result, err := ConvertHadolintToHDF(loadFixture(t, filepath.Join("input", name)), testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)
	return result
}

func requirementByID(t *testing.T, result *hdf.HDFResults, id string) hdf.EvaluatedRequirement {
	t.Helper()
	for _, b := range result.Baselines {
		for _, r := range b.Requirements {
			if r.ID == id {
				return r
			}
		}
	}
	t.Fatalf("no requirement with id %s", id)
	return hdf.EvaluatedRequirement{}
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "hadolint-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertHadolintToHDF(input, testVersion) },
		MinimalFixture: "real.json",
	})
}

func TestConvert_DocumentShape(t *testing.T) {
	result := convertFixture(t, "real.json")

	require.Len(t, result.Baselines, 1)
	b := result.Baselines[0]
	assert.Equal(t, "Hadolint Scan", b.Name, "a fixed scan label, never the scanned path")
	require.NotNil(t, b.Title)
	assert.Equal(t, "Hadolint Scan of Dockerfile", *b.Title)
	require.NotNil(t, b.ResultsChecksum)

	assert.Equal(t, "hadolint-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "hadolint", *result.Tool.Name)
	assert.Nil(t, result.Tool.Version, "hadolint output carries no version")

	require.Len(t, result.Components, 1)
	assert.Equal(t, "Dockerfile", result.Components[0].Name)
	assert.Equal(t, hdf.Repository, result.Components[0].Type)
}

// Four findings over three distinct rules: one requirement per rule, and the
// rule that fires twice keeps both results rather than collapsing them.
func TestConvert_GroupsByRuleKeepingEveryFinding(t *testing.T) {
	result := convertFixture(t, "real.json")
	b := result.Baselines[0]

	ids := make([]string, 0, len(b.Requirements))
	total := 0
	for _, r := range b.Requirements {
		ids = append(ids, r.ID)
		total += len(r.Results)
	}
	assert.Equal(t, []string{"DL3002", "DL3041", "DL3059"}, ids, "first-seen order")
	assert.Equal(t, 4, total, "every finding survives grouping")
	assert.Len(t, requirementByID(t, result, "DL3041").Results, 2)
}

func TestConvert_RequirementFields(t *testing.T) {
	req := requirementByID(t, convertFixture(t, "real.json"), "DL3002")

	require.NotNil(t, req.Title)
	assert.Equal(t, "Last USER should not be root", *req.Title)
	assert.InDelta(t, 0.5, req.Impact, 1e-9, "warning")

	require.Len(t, req.Descriptions, 1)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Equal(t, "Last USER should not be root", req.Descriptions[0].Data)

	require.NotNil(t, req.SourceLocation)
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "Dockerfile", *req.SourceLocation.Ref)
	require.NotNil(t, req.SourceLocation.Line)
	assert.InDelta(t, 11, *req.SourceLocation.Line, 1e-9)

	require.NotNil(t, req.Code, "the raw finding is kept so nothing the typed mapping drops is lost")
	var raw map[string]any
	require.NoError(t, json.Unmarshal([]byte(*req.Code), &raw))
	assert.Equal(t, "DL3002", raw["code"])

	require.Len(t, req.Results, 1)
	res := req.Results[0]
	assert.Equal(t, hdf.Failed, res.Status)
	assert.Equal(t, "File: Dockerfile | Line: 11 | Column: 1", res.CodeDesc)
	require.NotNil(t, res.Message)
	assert.Equal(t, "Last USER should not be root", *res.Message)

	require.NotNil(t, req.VerificationMethod)
	assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod)
}

func TestConvert_NistTagsFromTheMappingTable(t *testing.T) {
	result := convertFixture(t, "real.json")

	assert.Equal(t, []any{"AC-6"}, requirementByID(t, result, "DL3002").Tags["nist"])
	assert.Equal(t, []any{"CCI-000225"}, requirementByID(t, result, "DL3002").Tags["cci"])
	assert.Equal(t, []any{"CM-2"}, requirementByID(t, result, "DL3041").Tags["nist"])
	assert.Equal(t, []any{"CM-7"}, requirementByID(t, result, "DL3059").Tags["nist"])
}

// A shellcheck rule arrives in the same report and resolves from the same table.
func TestConvert_ShellcheckRulesShareTheTable(t *testing.T) {
	result := convertFixture(t, "shellcheck.json")
	req := requirementByID(t, result, "SC2154")
	assert.Equal(t, []any{"SA-11"}, req.Tags["nist"])
	assert.InDelta(t, 0.5, req.Impact, 1e-9)
}

// An unmapped rule takes the shared static-analysis fallback rather than an
// empty nist tag, which would drop it from every NIST-based view.
func TestConvert_UnmappedRuleTakesTheSharedFallback(t *testing.T) {
	input := []byte(`[{"code":"DL9999","column":1,"file":"Dockerfile","level":"error","line":3,"message":"A rule with no mapping"}]`)
	result, err := ConvertHadolintToHDF(input, testVersion)
	require.NoError(t, err)
	req := requirementByID(t, result, "DL9999")
	assert.Equal(t, hdfutil.StringsToInterfaces(shared.DefaultStaticAnalysisNIST), req.Tags["nist"])
	assert.NotEmpty(t, req.Tags["cci"])
	assert.InDelta(t, 0.7, req.Impact, 1e-9, "error")
}

// DL1000 is hadolint's parse-error pseudo-rule. It is deliberately absent from
// the mapping table and must resolve like any other unmapped rule.
func TestConvert_ParseErrorPseudoRule(t *testing.T) {
	input := []byte(`[{"code":"DL1000","column":7,"file":"Dockerfile","level":"error","line":1,"message":"unexpected 'F'"}]`)
	result, err := ConvertHadolintToHDF(input, testVersion)
	require.NoError(t, err)
	req := requirementByID(t, result, "DL1000")
	assert.Equal(t, hdfutil.StringsToInterfaces(shared.DefaultStaticAnalysisNIST), req.Tags["nist"])
	assert.Equal(t, "File: Dockerfile | Line: 1 | Column: 7", req.Results[0].CodeDesc,
		"the real column matters here, which is the one case hadolint does not hardcode it to 1")
}

func TestConvert_ImpactPerLevel(t *testing.T) {
	for level, want := range map[string]float64{
		"error": 0.7, "warning": 0.5, "info": 0.3, "style": 0.1, "": 0.0, "unheard-of": 0.0,
	} {
		input := []byte(`[{"code":"DL3000","column":1,"file":"Dockerfile","level":"` + level + `","line":1,"message":"m"}]`)
		result, err := ConvertHadolintToHDF(input, testVersion)
		require.NoError(t, err, "level %q", level)
		assert.InDelta(t, want, requirementByID(t, result, "DL3000").Impact, 1e-9, "level %q", level)
	}
}

// One component per distinct file: hadolint accepts several Dockerfiles in one
// run and tags every finding with the file it came from.
func TestConvert_ComponentPerDistinctFile(t *testing.T) {
	input := []byte(`[
	  {"code":"DL3000","column":1,"file":"a/Dockerfile","level":"warning","line":1,"message":"m"},
	  {"code":"DL3001","column":1,"file":"b/Dockerfile","level":"warning","line":2,"message":"n"},
	  {"code":"DL3002","column":1,"file":"a/Dockerfile","level":"warning","line":3,"message":"o"}
	]`)
	result, err := ConvertHadolintToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Components, 2)
	assert.Equal(t, "a/Dockerfile", result.Components[0].Name, "first-seen order")
	assert.Equal(t, "b/Dockerfile", result.Components[1].Name)
	require.NotNil(t, result.Baselines[0].Title)
	assert.Equal(t, "Hadolint Scan of 2 files", *result.Baselines[0].Title)
}

func TestConvert_EmptyFindings(t *testing.T) {
	result := convertFixture(t, "empty.json")
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "hadolint-no-findings", req.ID)
	require.NotNil(t, req.Title)
	assert.Equal(t, "No findings reported", *req.Title)
	assert.Zero(t, req.Impact)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Equal(t, "hadolint scanned the Dockerfile and reported zero findings.", req.Results[0].CodeDesc)
	assert.Empty(t, result.Components, "a clean run names no file, so there is nothing to identify")
}

func TestConvert_RejectsMalformedInput(t *testing.T) {
	for name, input := range map[string]string{
		"empty":              "",
		"not json":           "not json",
		"an object":          `{"code":"DL3000"}`,
		"wrong item":         `[{"code":42}]`,
		"json null":          "null",
		"line is a string":   `[{"code":"DL3002","line":"nope"}]`,
		"column is a bool":   `[{"code":"DL3002","column":true}]`,
		"level is a number":  `[{"code":"DL3002","level":3}]`,
		"message is a list":  `[{"code":"DL3002","message":["a"]}]`,
		"file is an object":  `[{"code":"DL3002","file":{}}]`,
		"line is fractional": `[{"code":"DL3002","line":1.5}]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ConvertHadolintToHDF([]byte(input), testVersion)
			assert.Error(t, err)
		})
	}
}

// hadolint can emit SARIF as well as JSON. A SARIF document routes to the
// shared converter rather than failing to parse as a findings array.
func TestConvert_SarifInputIsDelegated(t *testing.T) {
	sarifPath := filepath.Join(shared.GetConvertersDir(), "sarif-to-hdf", "fixtures", "input")
	matches, err := filepath.Glob(filepath.Join(sarifPath, "*.sarif"))
	require.NoError(t, err)
	require.NotEmpty(t, matches, "the sarif converter's fixtures are the shared corpus for this")

	data, err := os.ReadFile(matches[0])
	require.NoError(t, err)
	result, err := ConvertHadolintToHDF(data, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEqual(t, "Hadolint Scan", result.Baselines[0].Name, "delegated, not parsed as hadolint")
}

func TestSnapshots(t *testing.T) {
	// hadolint output carries no scan time of any kind.
	shared.RunSnapshotTests(t, "hadolint-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertHadolintToHDF(input, testVersion)
	}, "*")
}

// A findings array that decodes to nil is a malformed document, not a clean
// scan: encoding/json accepts the literal null for a slice without error, and
// an absent list cannot be distinguished from a passed no-findings report
// unless the nil is rejected explicitly. Decoding [] yields a non-nil empty
// slice, so a genuinely clean report still converts.
func TestConvert_JSONNullIsNotACleanReport(t *testing.T) {
	_, err := ConvertHadolintToHDF([]byte("null"), testVersion)
	require.Error(t, err)

	doc, err := ConvertHadolintToHDF([]byte("[]"), testVersion)
	require.NoError(t, err)
	require.Len(t, doc.Baselines[0].Requirements, 1, "an empty array is still a clean report")
}

func TestExpectedRequirementCount_JSONNullIsRejected(t *testing.T) {
	_, _, err := ExpectedRequirementCount([]byte("null"))
	assert.Error(t, err)
}

// The conversion caps its finding list, so the expected-count relation has to
// read the same capped list. A distinct rule code appearing only beyond the cap
// would otherwise be counted as expected and never emitted, and the fidelity
// check would reject a conversion that truncated exactly as designed.
func TestCapAppliesToTheExpectedCountAsWell(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < hdfutil.DefaultMaxItems; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"code":"DL3002","line":1}`)
	}
	b.WriteString(`,{"code":"DL3003","line":2}]`)
	input := []byte(b.String())

	want, _, err := ExpectedRequirementCount(input)
	require.NoError(t, err)

	doc, err := ConvertHadolintToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, want, len(doc.Baselines[0].Requirements),
		"the expected count and the conversion must read the same capped findings")
	assert.Equal(t, 1, want, "the rule beyond the cap is not converted, so it is not expected")
}

// A sparse finding and an explicitly null field both decode to zero values
// rather than erroring, so neither is malformed; the TypeScript guard matches.
func TestConvert_AcceptsSparseAndNullFields(t *testing.T) {
	for name, input := range map[string]string{
		"fields absent": `[{"code":"DL3002"}]`,
		"fields null":   `[{"code":"DL3002","line":null,"file":null}]`,
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := ConvertHadolintToHDF([]byte(input), testVersion)
			require.NoError(t, err)
			require.Len(t, doc.Baselines[0].Requirements, 1)
			assert.Equal(t, "DL3002", doc.Baselines[0].Requirements[0].ID)
		})
	}
}
