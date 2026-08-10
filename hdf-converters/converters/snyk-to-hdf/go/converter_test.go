package snyk

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

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "snyk-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertSnykToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

// ---- Minimal fixture: baseline structure ----

func TestConvertSnyk_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	// minimal.json has 8 unique vulnerability IDs (9 total entries)
	assert.Len(t, result.Baselines[0].Requirements, 8)
}

func TestConvertSnyk_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Snyk Scan", result.Baselines[0].Name)
}

func TestConvertSnyk_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "goof")
}

func TestConvertSnyk_BaselineSummary(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Summary)
	assert.Contains(t, *result.Baselines[0].Summary, "vulnerable dependency paths")
}

func TestConvertSnyk_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertSnyk_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "snyk-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertSnyk_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Snyk", *result.Tool.Name)
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
}

// ---- Severity → Impact mapping ----

func TestConvertSnyk_Severity(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// critical → 0.9 (npm:adm-zip:20180415)
	critical := shared.MustFindRequirement(t, reqs, "npm:adm-zip:20180415")
	assert.InDelta(t, 0.9, critical.Impact, 0.001)

	// high → 0.7 (SNYK-JS-ADMZIP-1065796)
	high := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")
	assert.InDelta(t, 0.7, high.Impact, 0.001)

	// medium → 0.5 (SNYK-JS-HIGHLIGHTJS-1045326)
	medium := shared.MustFindRequirement(t, reqs, "SNYK-JS-HIGHLIGHTJS-1045326")
	assert.InDelta(t, 0.5, medium.Impact, 0.001)

	// low → 0.3 (SNYK-JS-HBS-1566555)
	low := shared.MustFindRequirement(t, reqs, "SNYK-JS-HBS-1566555")
	assert.InDelta(t, 0.3, low.Impact, 0.001)
}

// ---- CWE → NIST mapping ----

func TestConvertSnyk_CweToNist(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// CWE-22 (Directory Traversal) should have a NIST mapping
	req := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")

	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
}

// ---- Deduplication ----

func TestConvertSnyk_Dedup(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// SNYK-JS-HANDLEBARS-534988 appears twice in the fixture → single requirement, 2 results
	req := shared.MustFindRequirement(t, reqs, "SNYK-JS-HANDLEBARS-534988")
	assert.Len(t, req.Results, 2, "should have 2 results for deduplicated vuln")
}

// ---- Dependency path in CodeDesc ----

func TestConvertSnyk_DependencyPath(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")
	require.NotEmpty(t, req.Results)

	// "from" for this vuln: ["goof@1.0.1", "adm-zip@0.4.7"]
	codeDesc := req.Results[0].CodeDesc
	assert.Contains(t, codeDesc, "goof@1.0.1")
	assert.Contains(t, codeDesc, "adm-zip@0.4.7")
}

// ---- Tags ----

func TestConvertSnyk_Tags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// npm:adm-zip:20180415 has CVE, CWE, and GHSA identifiers
	req := shared.MustFindRequirement(t, reqs, "npm:adm-zip:20180415")

	// CWE is now first-class (req.Cwe), not a tag
	_, hasCweid := req.Tags["cweid"]
	assert.False(t, hasCweid, "cweid tag removed — CWE now lives in requirement.cwe[]")

	// cve (renamed from cveid); CVE is not the requirement.id so it lives here
	cve, ok := req.Tags["cve"].([]string)
	require.True(t, ok, "cve should be []string")
	assert.Contains(t, cve, "CVE-2018-1002204")
	_, hasCveid := req.Tags["cveid"]
	assert.False(t, hasCveid, "cveid tag renamed to cve")

	// ghsaid
	ghsaid, ok := req.Tags["ghsaid"].([]string)
	require.True(t, ok, "ghsaid should be []string")
	assert.Contains(t, ghsaid, "GHSA-3v6h-hqm4-2rg6")

	// nist
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist should be present")
	assert.NotEmpty(t, nist)

	// cci
	cciSlice := hdfutil.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cciSlice, "cci should be present")
	assert.NotEmpty(t, cciSlice)
}

// ---- Structured CVSS ----

func TestConvertSnyk_Cvss(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")

	require.Len(t, req.Cvss, 1)
	cv := req.Cvss[0]
	assert.Equal(t, hdf.The31, cv.Version)
	require.NotNil(t, cv.BaseScore)
	assert.InDelta(t, 7.4, *cv.BaseScore, 0.001)
	require.NotNil(t, cv.BaseVector)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", *cv.BaseVector)
	require.NotNil(t, cv.BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityHigh, *cv.BaseSeverity)

	// Old CVSS-related tags must not be present
	_, hasBaseScore := req.Tags["cvss_base_score"]
	assert.False(t, hasBaseScore)
	_, hasCvss31 := req.Tags["cvss31"]
	assert.False(t, hasCvss31)
}

// ---- Structured CWE ----

func TestConvertSnyk_Cwe(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")

	assert.Equal(t, []string{"CWE-22"}, req.Cwe)
	// NIST mapping (derived from CWE) stays as a tag
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	assert.NotEmpty(t, nist)
}

// ---- buildSnykCvss branch coverage ----

func TestBuildSnykCvss_Branches(t *testing.T) {
	// Both absent → omitted
	assert.Nil(t, buildSnykCvss(SnykVuln{}))

	// Score present, vector absent → default version 3.1, no vector, no severity band absent-check
	scoreOnly := buildSnykCvss(SnykVuln{CvssScore: 5.5})
	require.Len(t, scoreOnly, 1)
	assert.Equal(t, hdf.The31, scoreOnly[0].Version)
	require.NotNil(t, scoreOnly[0].BaseScore)
	assert.InDelta(t, 5.5, *scoreOnly[0].BaseScore, 0.001)
	assert.Nil(t, scoreOnly[0].BaseVector)

	// Vector present, score zero → vector set, no base score
	vectorOnly := buildSnykCvss(SnykVuln{CVSSv3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
	require.Len(t, vectorOnly, 1)
	assert.Equal(t, hdf.The30, vectorOnly[0].Version)
	assert.Nil(t, vectorOnly[0].BaseScore)
	require.NotNil(t, vectorOnly[0].BaseVector)
}

// ---- Status: all results are Failed ----

func TestConvertSnyk_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all Snyk vulnerabilities should be Failed (vuln %s)", req.ID)
		}
	}
}

// ---- Default description ----

func TestConvertSnyk_Description(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.Contains(t, desc.Data, "adm-zip")
}

// ---- External references (refs[]) ----

func TestConvertSnyk_Refs(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")

	require.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://github.com/cthackers/adm-zip/commit/119dcad6599adccc77982feb14a0c7440fa63013", *req.Refs[0].URL)
}

func TestBuildSnykRefs_Branches(t *testing.T) {
	// No references → nil (field omitted)
	assert.Nil(t, buildSnykRefs(nil))
	assert.Nil(t, buildSnykRefs([]SnykReference{}))

	// Title-only reference (no URL) is skipped
	assert.Nil(t, buildSnykRefs([]SnykReference{{Title: "no link"}}))

	// URL present → one Reference per URL, title dropped
	refs := buildSnykRefs([]SnykReference{
		{Title: "a", URL: "https://example.com/a"},
		{Title: "b"},
		{Title: "c", URL: "https://example.com/c"},
	})
	require.Len(t, refs, 2)
	require.NotNil(t, refs[0].URL)
	assert.Equal(t, "https://example.com/a", *refs[0].URL)
	require.NotNil(t, refs[1].URL)
	assert.Equal(t, "https://example.com/c", *refs[1].URL)
}

// ---- requirement.code raw-finding passthrough ----

// TestConvertSnyk_Code pins the fields that have no other structured HDF home
// (exploit, language, semver, functions, disclosure/publication times) into the
// requirement.code raw passthrough, and asserts the serialization contract that
// keeps it byte-identical to the TS projection: two-space indent, no trailing
// newline, raw (unescaped) `&`/`<`/`>`, and the fixed leading field order.
func TestConvertSnyk_Code(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "npm:adm-zip:20180415")
	require.NotNil(t, req.Code, "requirement.code must carry the raw-finding passthrough")
	code := *req.Code

	// Serialization contract (byte-parity with TS JSON.stringify(obj, null, 2)).
	assert.True(t, strings.HasPrefix(code, "{\n  \"id\": "), "code must be two-space-indented JSON")
	assert.False(t, strings.HasSuffix(code, "\n"), "code must not have a trailing newline")

	// The parsed object carries the otherwise-lost fields verbatim.
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(code), &got))
	assert.Equal(t, "High", got["exploit"])
	assert.Equal(t, "js", got["language"])
	assert.Equal(t, "critical", got["severityWithCritical"])
	assert.Equal(t, "2018-04-14T21:00:00Z", got["disclosureTime"])
	assert.Equal(t, "2018-05-31T07:09:16Z", got["publicationTime"])

	semver, ok := got["semver"].(map[string]interface{})
	require.True(t, ok, "semver object preserved")
	assert.Equal(t, []interface{}{"<0.4.11"}, semver["vulnerable"])

	functions, ok := got["functions"].([]interface{})
	require.True(t, ok, "functions preserved")
	require.Len(t, functions, 1)
	fn := functions[0].(map[string]interface{})
	fnID := fn["functionId"].(map[string]interface{})
	// className was null in source → dropped by both Go omitempty and the TS
	// truthy check (they must agree for byte-parity).
	_, hasClassName := fnID["className"]
	assert.False(t, hasClassName, "null className is dropped")
	assert.Equal(t, "adm-zip.js", fnID["filePath"])
	assert.Equal(t, "module.exports.getEntry", fnID["functionName"])
	assert.Equal(t, []interface{}{">0.1.1 <0.4.11"}, fn["version"])
}

// TestBuildVulnCode_OmitsEmpty confirms the omitempty/truthy omission rules that
// keep Go and TS byte-identical: empty string, 0, false, and empty slices are
// all dropped; a present-but-empty identifiers object is still emitted.
func TestBuildVulnCode_OmitsEmpty(t *testing.T) {
	code := buildVulnCode(SnykVuln{ID: "X", CvssScore: 0, Malicious: false})
	assert.Equal(t, "{\n  \"id\": \"X\",\n  \"identifiers\": {}\n}", code)
}

// ---- upgradePath remediation description ----

func TestConvertSnyk_UpgradePathDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// SNYK-JS-ADMZIP-1065796 upgradePath is [false, "adm-zip@0.5.2"]
	withPath := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")
	desc := findDescription(withPath.Descriptions, "upgradePath")
	require.NotNil(t, desc, "expected an 'upgradePath' description")
	assert.Equal(t, "adm-zip@0.5.2", desc.Data)

	// SNYK-JS-HBS-1566555 has an empty upgradePath → no description emitted
	noPath := shared.MustFindRequirement(t, reqs, "SNYK-JS-HBS-1566555")
	assert.Nil(t, findDescription(noPath.Descriptions, "upgradePath"),
		"empty upgradePath must not emit an upgradePath description")
}

func TestFormatUpgradePath_Branches(t *testing.T) {
	// Empty / bool-only (structural noise) → ""
	assert.Equal(t, "", formatUpgradePath(nil))
	assert.Equal(t, "", formatUpgradePath([]interface{}{}))
	assert.Equal(t, "", formatUpgradePath([]interface{}{false}))

	// Single package step
	assert.Equal(t, "adm-zip@0.5.2", formatUpgradePath([]interface{}{false, "adm-zip@0.5.2"}))

	// Multi-step chain joined with " > ", empty strings dropped
	assert.Equal(t, "tap@11.1.5 > handlebars@4.5.3",
		formatUpgradePath([]interface{}{false, "tap@11.1.5", "", "handlebars@4.5.3"}))
}

// ---- Requirement title and ID ----

func TestConvertSnyk_RequirementTitleAndID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "SNYK-JS-ADMZIP-1065796")
	assert.Equal(t, "SNYK-JS-ADMZIP-1065796", req.ID)
	require.NotNil(t, req.Title)
	assert.Equal(t, "Directory Traversal", *req.Title)
}

// ---- Target ----

func TestConvertSnyk_Target(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "goof", result.Components[0].Name)
}

// ---- SARIF routing ----

func TestConvertSnyk_SarifRouting(t *testing.T) {
	// Load a SARIF fixture from the SARIF converter's fixtures
	sarifPath := filepath.Join(shared.GetConvertersDir(), "sarif-to-hdf", "fixtures", "input", "gosec.sarif")
	input, err := os.ReadFile(sarifPath)
	require.NoError(t, err, "Failed to read SARIF fixture")

	// Should be detected as SARIF and routed to the SARIF converter
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err, "SARIF input should be accepted")
	require.NotNil(t, result)

	// SARIF converter uses tool driver name as baseline name (not "Snyk Scan")
	require.Len(t, result.Baselines, 1)
	assert.NotEqual(t, "Snyk Scan", result.Baselines[0].Name)
}

func TestConvertSnyk_NativeNotRouted(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	// Native Snyk JSON uses "Snyk Scan" baseline name
	assert.Equal(t, "Snyk Scan", result.Baselines[0].Name)
}

// ---- Full fixture smoke tests ----

func TestConvertSnyk_FullFixtureLocal(t *testing.T) {
	input := loadFixture(t, "input/nodejs-goof-local.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// nodejs-goof-local.json has 94 unique vulnerability IDs (379 total entries)
	assert.Len(t, reqs, 94)

	// Spot-check deduplication: 379 total entries collapsed to 94 requirements
	totalResults := 0
	for _, req := range reqs {
		totalResults += len(req.Results)
	}
	assert.Equal(t, 379, totalResults, "total results should match total vulnerability entries")
}

func TestConvertSnyk_FullFixtureRemote(t *testing.T) {
	input := loadFixture(t, "input/nodejs-goof-remote.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	assert.NotEmpty(t, reqs)
	for _, req := range reqs {
		assert.NotEmpty(t, req.ID)
		assert.NotEmpty(t, req.Results)
	}
}

// ---- Empty vulnerabilities array ----

func TestConvertSnyk_EmptyVulnerabilities(t *testing.T) {
	input := []byte(`{
		"ok": true,
		"vulnerabilities": [],
		"projectName": "clean-project",
		"summary": "No known vulnerabilities"
	}`)
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)
	assert.Equal(t, "snyk-no-findings", result.Baselines[0].Requirements[0].ID)
	assert.Equal(t, hdf.Passed, result.Baselines[0].Requirements[0].Results[0].Status)
}

// ---- Helper: severityToImpact ----

func TestSeverityToImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"critical", 0.9},
		{"CRITICAL", 0.9},
		{"high", 0.7},
		{"HIGH", 0.7},
		{"medium", 0.5},
		{"MEDIUM", 0.5},
		{"low", 0.3},
		{"LOW", 0.3},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

func TestConvertSnyk_ControlType(t *testing.T) {
	input := loadFixture(t, "input/nodejs-goof-local.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

// countDistinctSnykVulnIDs walks the raw Snyk document — deliberately NOT the
// converter's structs — and returns the number of distinct vulnerabilities[].id
// values. Snyk's emission unit is the distinct vuln id (groupByID collapses
// every entry sharing an id into one requirement with many results), so a plain
// vulnerabilities count overshoots. Handles both single-project (object) and
// multi-project (array) input.
func countDistinctSnykVulnIDs(t *testing.T, input []byte) int {
	t.Helper()
	type project struct {
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	var projects []project
	if err := json.Unmarshal(input, &projects); err != nil {
		var single project
		require.NoError(t, json.Unmarshal(input, &single), "failed to parse Snyk JSON for anchor count")
		projects = []project{single}
	}
	distinct := make(map[string]struct{})
	for _, p := range projects {
		for _, v := range p.Vulnerabilities {
			distinct[v.ID] = struct{}{}
		}
	}
	return len(distinct)
}

// Ground-truth anchor: the converter emits one requirement per DISTINCT vuln id.
// The distinct count is derived independently of the converter's parser, so a
// silent under-extraction (e.g. dropping a vuln group) fails even when Go/TS
// golden parity agrees. nodejs-goof-local's 379 vulns collapse to 94 ids.
func TestConvertSnyk_DistinctVulnIDAnchor(t *testing.T) {
	input := loadFixture(t, "input/nodejs-goof-local.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countDistinctSnykVulnIDs(t, input),
		"nodejs-goof-local.json: one requirement per distinct vulnerabilities[].id")
}

func TestSnapshots(t *testing.T) {
	// Snyk output carries no scan time.
	shared.RunSnapshotTests(t, "snyk-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertSnykToHDF(input, "1.0.0")
	}, "*")
}

func TestConvertSnyk_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q expected verificationMethod=automated", req.ID)
	}
}

func TestConvertSnyk_NoVulnerabilities(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertSnykToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "snyk-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Snyk")
	assert.Contains(t, req.Results[0].CodeDesc, "scanned")
	assert.Contains(t, req.Results[0].CodeDesc, "vulnerable components")
	assert.Contains(t, req.Results[0].CodeDesc, "clean-project")

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "clean-project", result.Components[0].Name)
}
