package semgrep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "1.0.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func convertFixture(t *testing.T, name string) *hdf.HDFResults {
	t.Helper()
	out, err := ConvertSemgrepToHDF(loadFixture(t, name), testVersion)
	require.NoError(t, err)
	require.NotNil(t, out)
	return out
}

func findReq(reqs []hdf.EvaluatedRequirement, fragment string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if len(fragment) > 0 && contains(reqs[i].ID, fragment) {
			return &reqs[i]
		}
	}
	return nil
}

func contains(haystack, needle string) bool {
	return len(needle) <= len(haystack) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// ---- Contract ----

func TestRejectsEmptyInput(t *testing.T) {
	_, err := ConvertSemgrepToHDF([]byte(""), testVersion)
	require.Error(t, err)
}

func TestRejectsInvalidJSON(t *testing.T) {
	_, err := ConvertSemgrepToHDF([]byte("not valid json"), testVersion)
	require.Error(t, err)
}

func TestRejectsNonSemgrepDocument(t *testing.T) {
	_, err := ConvertSemgrepToHDF([]byte(`{"foo":1}`), testVersion)
	require.ErrorContains(t, err, "does not look like a Semgrep report")
}

func TestConvertsMinimalFixture(t *testing.T) {
	out := convertFixture(t, "minimal.json")
	require.Len(t, out.Baselines, 1)
	assert.Equal(t, "Semgrep Scan", out.Baselines[0].Name)
}

// ---- Mapping behaviour ----

func TestGroupsFindingsOneRequirementPerRule(t *testing.T) {
	out := convertFixture(t, "real.json")
	reqs := out.Baselines[0].Requirements
	// Two rules plus the always-present coverage record.
	assert.Len(t, reqs, 3)
	assert.Equal(t, coverageID, reqs[len(reqs)-1].ID)
	seen := map[string]bool{}
	for _, r := range reqs {
		assert.False(t, seen[r.ID], "duplicate requirement id %s", r.ID)
		seen[r.ID] = true
	}
}

func TestMapsSeverityToImpact(t *testing.T) {
	out := convertFixture(t, "real.json")
	reqs := out.Baselines[0].Requirements
	assert.Equal(t, 0.7, findReq(reqs, "subprocess-shell-true").Impact)
	assert.Equal(t, 0.5, findReq(reqs, "dynamic-urllib-use-detected").Impact)
}

func TestResolvesNistAndCciTags(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	nist := shared.NISTTagsFromMap(req.Tags)
	assert.NotEmpty(t, nist)
	ccis, ok := req.Tags["cci"].([]string)
	require.True(t, ok, "cci tag missing or wrong type")
	assert.NotEmpty(t, ccis)
}

func TestNormalizesOwaspStringOrArray(t *testing.T) {
	out := convertFixture(t, "real.json")
	reqs := out.Baselines[0].Requirements
	// real.json deliberately carries one rule with an array and one with a string
	arrayForm, ok := findReq(reqs, "subprocess-shell-true").Tags["owasp"].([]string)
	require.True(t, ok)
	assert.Len(t, arrayForm, 3)
	stringForm, ok := findReq(reqs, "dynamic-urllib-use-detected").Tags["owasp"].([]string)
	require.True(t, ok)
	assert.Len(t, stringForm, 1)
}

func TestSemgrepMetadataImpactDoesNotShadowHdfImpact(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	_, shadowed := req.Tags["impact"]
	assert.False(t, shadowed, "semgrep metadata.impact must not be tagged as impact")
	assert.Equal(t, "LOW", req.Tags["semgrepImpact"])
}

func TestPreservesCrossFrameworkMetadata(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "dynamic-urllib-use-detected")
	require.NotNil(t, req)
	assert.Equal(t, "LOW", req.Tags["likelihood"])
	assert.Equal(t, "LOW", req.Tags["confidence"])
	assert.NotNil(t, req.Tags["asvs"])
	assert.NotNil(t, req.Tags["vulnerabilityClass"])
}

func TestReportsEveryFindingAsFailed(t *testing.T) {
	out := convertFixture(t, "real.json")
	for _, req := range out.Baselines[0].Requirements {
		if req.ID == coverageID {
			continue
		}
		for _, res := range req.Results {
			assert.Equal(t, hdf.Failed, res.Status)
		}
	}
}

func TestNeverEmitsRedactedPlaceholder(t *testing.T) {
	out := convertFixture(t, "real.json")
	for _, req := range out.Baselines[0].Requirements {
		for _, res := range req.Results {
			if res.Message != nil {
				assert.NotContains(t, *res.Message, redactedPlaceholder)
			}
		}
	}
}

func TestRecordsLocationInCodeDesc(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	assert.Contains(t, req.Results[0].CodeDesc, "app/handlers.py")
	assert.Contains(t, req.Results[0].CodeDesc, "7")
}

func TestEmptyScanProducesNoFindingsRequirement(t *testing.T) {
	out := convertFixture(t, "empty.json")
	reqs := out.Baselines[0].Requirements
	require.Len(t, reqs, 2)
	assert.Equal(t, "semgrep-no-findings", reqs[0].ID)
	assert.Equal(t, hdf.Passed, reqs[0].Results[0].Status)
	assert.Equal(t, coverageID, reqs[1].ID)
}

func TestScanErrorsBecomeTheirOwnRequirement(t *testing.T) {
	out := convertFixture(t, "errors.json")
	req := findReq(out.Baselines[0].Requirements, scanErrorsID)
	require.NotNil(t, req)
	assert.Len(t, req.Results, 2)
	// Both entries in errors.json are level "warn" (advisory PartialParsing):
	// the files were partially analyzed, which is a genuine non-evaluation of
	// those paths, not a scan failure — so they must not dominate worst-wins.
	for _, res := range req.Results {
		assert.Equal(t, hdf.NotReviewed, res.Status)
		assert.Contains(t, *res.Message, "warn")
	}
}

func TestErrorLevelDrivesResultStatus(t *testing.T) {
	req := buildErrorsRequirement([]ScanError{
		{Message: "fatal", Level: "error", Type: "SemgrepError"},
		{Message: "advisory", Level: "warn", Type: []any{"PartialParsing", []any{}}},
		{Message: "unlabeled", Type: "SemgrepError"},
	}, time.Now().UTC())
	require.Len(t, req.Results, 3)
	assert.Equal(t, hdf.Error, req.Results[0].Status)
	assert.Equal(t, hdf.NotReviewed, req.Results[1].Status)
	assert.Equal(t, hdf.Error, req.Results[2].Status)
}

func TestScanErrorsRequirementAbsentWhenNoErrors(t *testing.T) {
	out := convertFixture(t, "real.json")
	assert.Nil(t, findReq(out.Baselines[0].Requirements, scanErrorsID))
}

func TestTitleDerivedFromRuleId(t *testing.T) {
	assert.Equal(t, "Subprocess Shell True", titleFor("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"))
	assert.Equal(t, "Rule", titleFor("rule"))
}

func TestStringOrSliceDecodesBothForms(t *testing.T) {
	var s StringOrSlice
	require.NoError(t, s.UnmarshalJSON([]byte(`"one"`)))
	assert.Equal(t, StringOrSlice{"one"}, s)
	require.NoError(t, s.UnmarshalJSON([]byte(`["a","b"]`)))
	assert.Equal(t, StringOrSlice{"a", "b"}, s)
	require.NoError(t, s.UnmarshalJSON([]byte(`{"unexpected":true}`)))
	assert.Nil(t, s)
}

// ---- Golden snapshots (TS<->Go parity) ----

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "semgrep-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertSemgrepToHDF(input, testVersion)
	}, "*")
}

// ---- Edge cases ----

func TestImpactForFallsBackToModerate(t *testing.T) {
	assert.Equal(t, defaultImpact, impactFor(Result{}))
	assert.Equal(t, defaultImpact, impactFor(Result{Extra: Extra{Severity: "NOVEL"}}))
	assert.Equal(t, defaultImpact, impactFor(Result{Extra: Extra{Severity: redactedPlaceholder}}))
	assert.Equal(t, 0.9, impactFor(Result{Extra: Extra{Severity: "CRITICAL"}}))
}

func TestSeverityGoesThroughSharedAliasTable(t *testing.T) {
	// error/warning/info are semgrep-specific aliases (mirroring sarif's
	// error/warning/note tiers); critical/high/medium/low resolve through the
	// canonical shared map. Prototype-named tokens are ordinary unknowns.
	cases := map[string]float64{
		"ERROR": 0.7, "WARNING": 0.5, "INFO": 0.3,
		"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3,
		"NOVEL": 0.5, "constructor": 0.5, "__proto__": 0.5,
	}
	for sev, want := range cases {
		assert.Equal(t, want, impactFor(Result{Extra: Extra{Severity: LenientString(sev)}}), sev)
	}
}

func TestAbsentSeverityGetsUnratedMarker(t *testing.T) {
	input := []byte(`{"results":[
		{"check_id":"a.unrated","path":"a.py","start":{"line":1},"extra":{"message":"m"}},
		{"check_id":"a.redacted","path":"a.py","start":{"line":2},"extra":{"message":"m","severity":"requires login"}},
		{"check_id":"a.novel","path":"a.py","start":{"line":3},"extra":{"message":"m","severity":"NOVEL"}},
		{"check_id":"a.rated","path":"a.py","start":{"line":4},"extra":{"message":"m","severity":"HIGH"}}
	],"errors":[],"paths":{"scanned":["a.py"]}}`)
	out, err := ConvertSemgrepToHDF(input, testVersion)
	require.NoError(t, err)
	reqs := out.Baselines[0].Requirements
	assert.Equal(t, shared.UnratedSeverityValue, findReq(reqs, "a.unrated").Tags[shared.UnratedSeverityTag])
	assert.Equal(t, shared.UnratedSeverityValue, findReq(reqs, "a.redacted").Tags[shared.UnratedSeverityTag])
	_, novelMarked := findReq(reqs, "a.novel").Tags[shared.UnratedSeverityTag]
	assert.False(t, novelMarked, "unrecognized tokens are not unrated")
	_, ratedMarked := findReq(reqs, "a.rated").Tags[shared.UnratedSeverityTag]
	assert.False(t, ratedMarked)
}

func TestCodeDescVariants(t *testing.T) {
	assert.Equal(t, "Path: unknown", codeDescFor(Result{}))
	assert.Equal(t, "Path: a.py", codeDescFor(Result{Path: "a.py"}))
	assert.Equal(t, "Path: a.py, line 4",
		codeDescFor(Result{Path: "a.py", Start: Position{Line: 4}, End: Position{Line: 4}}))
	assert.Equal(t, "Path: a.py, lines 4-9",
		codeDescFor(Result{Path: "a.py", Start: Position{Line: 4}, End: Position{Line: 9}}))
}

func TestMessageForSkipsRedactedFields(t *testing.T) {
	assert.Equal(t, "", messageFor(Result{Extra: Extra{Lines: redactedPlaceholder}}))
	assert.Contains(t, messageFor(Result{Extra: Extra{Lines: "x = 1"}}), "Matched code:")
	assert.Contains(t, messageFor(Result{Extra: Extra{Fix: "False"}}), "replace the matched code with")
}

func TestErrorsRequirementHandlesOddTypeShapes(t *testing.T) {
	req := buildErrorsRequirement([]ScanError{
		{Message: "a", Type: []any{"PartialParsing", []any{}}},
		{Message: "b", Type: "PlainString"},
		{Message: "c"},
	}, time.Now().UTC())
	require.Len(t, req.Results, 3)
	assert.Contains(t, *req.Results[0].Message, "PartialParsing")
	assert.Contains(t, *req.Results[1].Message, "PlainString")
	assert.Contains(t, *req.Results[2].Message, "Unknown")
	assert.Equal(t, "Path: unknown", req.Results[2].CodeDesc)
}

func TestSkipsFindingsWithoutCheckId(t *testing.T) {
	input := []byte(`{"results":[{"path":"a.py"}],"errors":[],"paths":{"scanned":["a.py"]}}`)
	out, err := ConvertSemgrepToHDF(input, testVersion)
	require.NoError(t, err)
	// The malformed finding is skipped, leaving the no-findings placeholder
	// plus the always-present coverage record.
	require.Len(t, out.Baselines[0].Requirements, 2)
	assert.Equal(t, "semgrep-no-findings", out.Baselines[0].Requirements[0].ID)
}

func TestReferencesDeduplicated(t *testing.T) {
	urls := referencesFor(Metadata{
		References: StringOrSlice{"https://a", "https://a"},
		Source:     "https://a",
		Shortlink:  "https://b",
		ASVS:       map[string]any{"control_url": "https://c"},
	})
	assert.Equal(t, []string{"https://a", "https://b", "https://c"}, urls)
}

func TestRejectsTruncatedJSON(t *testing.T) {
	_, err := ConvertSemgrepToHDF([]byte(`{"results":`), testVersion)
	require.Error(t, err)
}

// ---- Remediation: robustness, parity, and field homes ----

func TestRejectsNullContainers(t *testing.T) {
	for _, input := range []string{
		`{"results":null,"errors":[],"paths":{"scanned":[]}}`,
		`{"results":[],"errors":null,"paths":{"scanned":[]}}`,
		`{"results":null,"errors":null}`,
	} {
		_, err := ConvertSemgrepToHDF([]byte(input), testVersion)
		require.ErrorContains(t, err, "does not look like a Semgrep report", input)
	}
}

func TestConvertAndDetectAgreeOnRejections(t *testing.T) {
	rejections := []string{
		`{"foo":1}`,
		`{"results":null,"errors":[],"paths":{"scanned":[]}}`,
		`{"results":[],"errors":null,"paths":{"scanned":[]}}`,
	}
	for _, input := range rejections {
		var obj map[string]any
		require.NoError(t, json.Unmarshal([]byte(input), &obj))
		assert.Equal(t, 0.0, fingerprintObject(obj), "fingerprint must reject %s", input)
		_, err := ConvertSemgrepToHDF([]byte(input), testVersion)
		require.Error(t, err, "convert must reject what detection rejects: %s", input)
	}
	for _, fixture := range []string{"minimal.json", "real.json", "errors.json", "empty.json"} {
		data := loadFixture(t, fixture)
		var obj map[string]any
		require.NoError(t, json.Unmarshal(data, &obj))
		assert.Greater(t, fingerprintObject(obj), 0.5, "fingerprint must accept %s", fixture)
		_, err := ConvertSemgrepToHDF(data, testVersion)
		require.NoError(t, err, "convert must accept %s", fixture)
	}
}

func TestLenientMetadataDecoding(t *testing.T) {
	// One wrong-typed freeform metadata value must never abort the whole
	// conversion: metadata is arbitrary rule-author YAML.
	inputs := []string{
		`{"results":[{"check_id":"a.b","path":"a.py","start":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":{"confidence":3}}}],"errors":[],"paths":{"scanned":["a.py"]}}`,
		`{"results":[{"check_id":"a.b","path":"a.py","start":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":{"asvs":[]}}}],"errors":[],"paths":{"scanned":["a.py"]}}`,
		`{"results":[{"check_id":"a.b","path":"a.py","start":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":"oops"}}],"errors":[],"paths":{"scanned":["a.py"]}}`,
		`{"results":[{"check_id":"a.b","path":"a.py","start":{"line":"7"},"extra":{"message":"m","severity":"ERROR"}}],"errors":[],"paths":{"scanned":["a.py"]}}`,
	}
	for _, input := range inputs {
		out, err := ConvertSemgrepToHDF([]byte(input), testVersion)
		require.NoError(t, err, input)
		require.NotNil(t, findReq(out.Baselines[0].Requirements, "a.b"), input)
	}
}

func TestMixedTypeArraysKeepStringEntries(t *testing.T) {
	var s StringOrSlice
	require.NoError(t, s.UnmarshalJSON([]byte(`["CWE-89: SQL Injection", 5]`)))
	assert.Equal(t, StringOrSlice{"CWE-89: SQL Injection"}, s)

	input := []byte(`{"results":[{"check_id":"a.b","path":"a.py","start":{"line":1},
		"extra":{"message":"m","severity":"ERROR","metadata":{"cwe":["CWE-89: SQL Injection",5],"references":["https://x",7]}}}],
		"errors":[],"paths":{"scanned":["a.py"]}}`)
	out, err := ConvertSemgrepToHDF(input, testVersion)
	require.NoError(t, err)
	req := findReq(out.Baselines[0].Requirements, "a.b")
	require.NotNil(t, req)
	assert.Equal(t, []string{"CWE-89: SQL Injection"}, req.Tags["cwe"])
	nist := shared.NISTTagsFromMap(req.Tags)
	assert.Contains(t, nist, "SI-10", "CWE-89 must drive the NIST mapping, not the static fallback")
	assert.NotContains(t, nist, "SA-11")
}

func TestCweTagOmittedWhenAbsent(t *testing.T) {
	input := []byte(`{"results":[{"check_id":"local.rule","path":"a.py","start":{"line":1},"extra":{"message":"m","severity":"WARNING"}}],"errors":[],"paths":{"scanned":["a.py"]}}`)
	out, err := ConvertSemgrepToHDF(input, testVersion)
	require.NoError(t, err)
	req := findReq(out.Baselines[0].Requirements, "local.rule")
	require.NotNil(t, req)
	_, present := req.Tags["cwe"]
	assert.False(t, present, "tags.cwe must be omitted, not null, when the rule has no CWE metadata")
}

func TestCweFieldNormalizedToCatalogForm(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Cwe)
	for _, entry := range req.Cwe {
		assert.Regexp(t, `^CWE-[1-9]\d*$`, entry, "cwe[] uses CWE-N catalog form")
	}
}

func TestSourceLocationFromFirstOccurrence(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	require.NotNil(t, req.SourceLocation)
	assert.Equal(t, "app/handlers.py", *req.SourceLocation.Ref)
	require.NotNil(t, req.SourceLocation.Line)
	assert.Equal(t, 7.0, *req.SourceLocation.Line)
}

func TestReferencesEmittedAsRefs(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	require.NotEmpty(t, req.Refs, "reference URLs belong in refs[], the structured home")
	for _, ref := range req.Refs {
		require.NotNil(t, ref.URL)
		assert.Contains(t, *ref.URL, "http")
	}
	_, inTags := req.Tags["references"]
	assert.False(t, inTags, "refs[] replaces the tags.references copy")
}

func TestCodeCarriesRawFinding(t *testing.T) {
	out := convertFixture(t, "real.json")
	req := findReq(out.Baselines[0].Requirements, "subprocess-shell-true")
	require.NotNil(t, req)
	require.NotNil(t, req.Code)
	assert.Contains(t, *req.Code, "subprocess-shell-true")
	assert.Contains(t, *req.Code, "\"check_id\"")
}

func TestCoverageRequirementAlwaysPresent(t *testing.T) {
	for _, fixture := range []string{"minimal.json", "real.json", "errors.json", "empty.json"} {
		out := convertFixture(t, fixture)
		req := findReq(out.Baselines[0].Requirements, coverageID)
		require.NotNil(t, req, "%s must carry the coverage record", fixture)
		assert.Equal(t, 0.0, req.Impact)
		require.Len(t, req.Results, 1)
		assert.Equal(t, hdf.NotApplicable, req.Results[0].Status)
		assert.Contains(t, req.Results[0].CodeDesc, "violations only")
	}
}

func TestZeroFindingsWithErrorsKeepsCleanScanStatement(t *testing.T) {
	input := []byte(`{"results":[],"errors":[{"message":"partial","level":"warn","type":["PartialParsing",[]],"path":"a.py"}],"paths":{"scanned":["a.py","b.py"]}}`)
	out, err := ConvertSemgrepToHDF(input, testVersion)
	require.NoError(t, err)
	reqs := out.Baselines[0].Requirements
	require.NotNil(t, findReq(reqs, "semgrep-no-findings"), "clean-scan statement must survive scan errors")
	require.NotNil(t, findReq(reqs, scanErrorsID))
	require.NotNil(t, findReq(reqs, coverageID))
}

func TestTitleParityEdges(t *testing.T) {
	assert.Equal(t, "Foo Bar Baz", titleFor("python.lang.foo--bar_-baz"))
	assert.Equal(t, "Eval/exec Check", titleFor("rules.eval/exec-check"))
}

func TestToolFormatOmitted(t *testing.T) {
	out := convertFixture(t, "minimal.json")
	require.NotNil(t, out.Tool)
	assert.Nil(t, out.Tool.Format, "JSON is an encoding, not a format specification")
}

func TestSarifInputRoutesToSarifConverter(t *testing.T) {
	sarifPath := filepath.Join(shared.GetConvertersDir(), "sarif-to-hdf", "fixtures", "input", "semgrep.sarif")
	input, err := os.ReadFile(sarifPath)
	require.NoError(t, err)
	out, err := ConvertSemgrepToHDF(input, testVersion)
	require.NoError(t, err, "SARIF input must be delegated, not rejected")
	require.Len(t, out.Baselines, 1)
	assert.Equal(t, "Semgrep OSS", out.Baselines[0].Name, "the SARIF converter names the baseline after the driver")
}

func TestNativeInputNotRoutedToSarif(t *testing.T) {
	out := convertFixture(t, "real.json")
	assert.Equal(t, "Semgrep Scan", out.Baselines[0].Name)
}
