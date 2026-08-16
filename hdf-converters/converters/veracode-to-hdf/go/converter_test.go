package veracode

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(shared.GetConvertersDir(), "veracode-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "Failed to read fixture: %s", name)
	return data
}

func TestConvertVeracodeToHDF_Sample(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify generator
	require.NotNil(t, result.Generator)
	assert.Equal(t, "veracode-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)

	// Verify tool
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Veracode", *result.Tool.Name)

	// Should have exactly 1 baseline
	require.Len(t, result.Baselines, 1, "Should have 1 baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "Veracode Scan", baseline.Name)

	// Should have target
	require.Len(t, result.Components, 1)
	assert.Equal(t, hdf.Application, result.Components[0].Type)

	// CWE-based controls: 14 categories (categoryid 12 appears at both severity 3 and 2)
	// CVE-based controls: 39 unique CVEs = 53 total
	totalRequirements := len(baseline.Requirements)
	assert.Greater(t, totalRequirements, 0, "Should have requirements")

	// Write output for differential testing
	shared.WriteOutput(t, "veracode-to-hdf", "veracode.json", result)
}

func TestConvertVeracodeToHDF_CWEControls(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]

	// Find a CWE-based control: categoryid "18" = "Command or Argument Injection"
	var cweControl *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "18" {
			cweControl = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, cweControl, "Should have CWE control with categoryid 18")
	require.NotNil(t, cweControl.Title)
	assert.Equal(t, "Command or Argument Injection", *cweControl.Title)

	// Severity level 5 maps to impact 0.9
	assert.Equal(t, 0.9, cweControl.Impact)

	// Should have results (static flaws)
	assert.Greater(t, len(cweControl.Results), 0, "Should have flaw results")
	// All results should be Failed
	for _, r := range cweControl.Results {
		assert.Equal(t, hdf.Failed, r.Status)
	}

	// Should have NIST tags from CWE mapping
	nistTags, ok := cweControl.Tags["nist"]
	assert.True(t, ok, "Should have nist tags")
	assert.NotEmpty(t, nistTags, "NIST tags should not be empty")

	// Should have descriptions
	assert.Greater(t, len(cweControl.Descriptions), 0, "Should have descriptions")
}

func TestConvertVeracodeToHDF_StandardsTags(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	reqs := result.Baselines[0].Requirements

	findReq := func(id string) *hdf.EvaluatedRequirement {
		for i := range reqs {
			if reqs[i].ID == id {
				return &reqs[i]
			}
		}
		return nil
	}

	// Category 18 ("Command or Argument Injection") has one CWE (78) carrying
	// five of the six standards cross-references. Each becomes a discrete tag.
	cat18 := findReq("18")
	require.NotNil(t, cat18, "Should have CWE control with categoryid 18")
	assert.Equal(t, []string{"1347"}, cat18.Tags["owasp"], "owasp tag")
	assert.Equal(t, []string{"864"}, cat18.Tags["sans"], "sans tag")
	assert.Equal(t, []string{"1165"}, cat18.Tags["certc"], "certc tag")
	assert.Equal(t, []string{"875"}, cat18.Tags["certcpp"], "certcpp tag")
	assert.Equal(t, []string{"1134"}, cat18.Tags["certjava"], "certjava tag")

	// owaspmobile is absent from every fixture CWE (NOT-IN-SOURCE): key omitted.
	_, hasMobile := cat18.Tags["owaspmobile"]
	assert.False(t, hasMobile, "owaspmobile tag should be omitted when absent")

	// Category 7 ("API Abuse") has a CWE (245) with no standards attributes:
	// none of the discrete standards keys should be present.
	cat7 := findReq("7")
	require.NotNil(t, cat7, "Should have CWE control with categoryid 7")
	for _, key := range []string{"owasp", "sans", "certc", "certcpp", "certjava", "owaspmobile"} {
		_, ok := cat7.Tags[key]
		assert.Falsef(t, ok, "%s tag should be omitted when no CWE carries it", key)
	}
}

func TestConvertVeracodeToHDF_StandardsTagsDedup(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	// Category 21 ("CRLF Injection") has three CWEs whose owasp attrs are
	// 1347, 1347, 1355 — distinct values collapse to two in appearance order.
	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "21" {
			assert.Equal(t, []string{"1347", "1355"}, req.Tags["owasp"], "distinct owasp values in appearance order")
			return
		}
	}
	t.Fatal("Should have CWE control with categoryid 21")
}

func TestConvertVeracodeToHDF_CVEControls(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]

	// Find a CVE-based control
	var cveControl *hdf.EvaluatedRequirement
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == "CVE-2017-1000487" {
			cveControl = &baseline.Requirements[i]
			break
		}
	}
	require.NotNil(t, cveControl, "Should have CVE control CVE-2017-1000487")
	require.NotNil(t, cveControl.Title)
	assert.Equal(t, "CVE-2017-1000487", *cveControl.Title)

	// Should have impact mapped from severity
	assert.Greater(t, cveControl.Impact, 0.0, "Should have non-zero impact")

	// Should have at least one failed result (one per affected component)
	assert.Greater(t, len(cveControl.Results), 0)
	for _, r := range cveControl.Results {
		assert.Equal(t, hdf.Failed, r.Status)
	}

	// Should have NIST tags
	nistTags, ok := cveControl.Tags["nist"]
	assert.True(t, ok, "Should have nist tags")
	assert.NotEmpty(t, nistTags, "NIST tags should not be empty")
}

func TestConvertVeracodeToHDF_SeverityImpactMapping(t *testing.T) {
	tests := []struct {
		level    string
		expected float64
	}{
		{"5", 0.9},
		{"4", 0.7},
		{"3", 0.5},
		{"2", 0.3},
		{"1", 0.1},
		{"0", 0.0},
	}

	for _, tt := range tests {
		t.Run("level_"+tt.level, func(t *testing.T) {
			got := veracodeSeverityToImpact(tt.level)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "veracode-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertVeracodeToHDF(input, testConverterVersion) },
		MinimalFixture: "veracode.xml",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertVeracodeToHDF_SummaryReport(t *testing.T) {
	summaryXML := []byte(`<?xml version="1.0" encoding="ISO-8859-1"?>
<summaryreport xmlns="https://www.veracode.com/schema/reports/export/1.0">
</summaryreport>`)

	result, err := ConvertVeracodeToHDF(summaryXML, testConverterVersion)
	assert.Error(t, err, "Should reject summary reports")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "summary")
}

func TestConvertVeracodeToHDF_ResultsChecksum(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	// Each baseline should have a results checksum
	assert.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

func TestConvertVeracodeToHDF_Timestamp(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.NotNil(t, result.Timestamp, "Should have timestamp from first_build_submitted_date")
}

func TestConvertVeracodeToHDF_AllFlawsAccountedFor(t *testing.T) {
	input := loadFixture(t, "veracode.xml")

	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	baseline := result.Baselines[0]

	// Count total results across all requirements
	totalResults := 0
	cweControlCount := 0
	cveControlCount := 0
	for _, req := range baseline.Requirements {
		totalResults += len(req.Results)
		// CVE controls have IDs starting with "CVE-" or "SRCCLR-"
		if len(req.ID) > 4 && (req.ID[:4] == "CVE-" || req.ID[:7] == "SRCCLR-") {
			cveControlCount++
		} else {
			cweControlCount++
		}
	}

	// The fixture has 194 static flaws + 41 SCA vulnerabilities
	// CWE controls: 14 categories (categoryid 12 appears at severity 3 and 2)
	// CVE controls: 39 unique CVEs (grouped by cve_id across components)
	assert.Equal(t, 14, cweControlCount, "Should have 14 CWE-based controls (categoryid 12 appears at 2 severity levels)")
	assert.Equal(t, 39, cveControlCount, "Should have 39 CVE-based controls")

	// Total flaw results from CWE controls should be 194
	cweResultCount := 0
	for _, req := range baseline.Requirements {
		if len(req.ID) <= 4 || (req.ID[:4] != "CVE-" && (len(req.ID) < 7 || req.ID[:7] != "SRCCLR-")) {
			cweResultCount += len(req.Results)
		}
	}
	assert.Equal(t, 194, cweResultCount, "CWE controls should have 194 total flaw results")
}

func TestConvertVeracodeToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertVeracodeToHDF(input, testConverterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestConvertVeracodeToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
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

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "veracode-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertVeracodeToHDF(input, "1.0.0")
	})
}

// countVeracodeEmissionUnits walks the raw Veracode XML generically — NOT via
// the converter's structs — and returns the number of requirements the
// converter should emit: one per CWE <category> element plus one per DISTINCT
// SCA cve_id. The CWE side emits per-category unconditionally; the CVE side
// groups/dedups by cve_id across components (skipping components whose
// vulnerabilities attr is "0"), so a plain <vulnerability> count would overshoot.
func countVeracodeEmissionUnits(t *testing.T, input []byte) int {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(input))
	dec.Strict = false
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	categories := 0
	distinctCVE := make(map[string]struct{})
	componentSkipped := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "veracode anchor: XML token error")
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "category":
			categories++
		case "component":
			componentSkipped = attr(se, "vulnerabilities") == "0"
		case "vulnerability":
			if componentSkipped {
				continue
			}
			if cve := attr(se, "cve_id"); cve != "" {
				distinctCVE[cve] = struct{}{}
			}
		}
	}
	return categories + len(distinctCVE)
}

func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// Ground-truth anchor: the converter emits one requirement per CWE <category>
// plus one per distinct SCA cve_id. The count is derived independently of the
// converter's parser, so a silent under-extraction fails even when Go/TS golden
// parity agrees. veracode.xml carries 14 categories + 39 distinct CVEs = 53.
func TestConvertVeracodeToHDF_EmissionAnchor(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countVeracodeEmissionUnits(t, input),
		"veracode.xml: one requirement per CWE category + one per distinct SCA cve_id")
}

func TestConvertVeracodeToHDF_NoFindings(t *testing.T) {
	input := loadFixture(t, "empty.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "veracode-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Veracode")
	assert.Contains(t, req.Results[0].CodeDesc, "CleanApp")
}

// synthesizeFlawCode branch coverage: every combination of function prototype
// and source locus, including the NOT-IN-SOURCE case (neither present).
func TestSynthesizeFlawCode(t *testing.T) {
	tests := []struct {
		name string
		flaw Flaw
		want string
	}{
		{
			name: "prototype and full locus",
			flaw: Flaw{FunctionPrototype: "String ping(String)", SourceFilePath: "com/x/", SourceFile: "A.java", Line: "53"},
			want: "String ping(String) at com/x/A.java:53",
		},
		{
			name: "prototype only, no locus",
			flaw: Flaw{FunctionPrototype: "String ping(String)"},
			want: "String ping(String)",
		},
		{
			name: "locus only, no prototype",
			flaw: Flaw{SourceFilePath: "com/x/", SourceFile: "A.java", Line: "53"},
			want: "com/x/A.java:53",
		},
		{
			name: "prototype and locus but no line",
			flaw: Flaw{FunctionPrototype: "String ping(String)", SourceFilePath: "com/x/", SourceFile: "A.java"},
			want: "String ping(String) at com/x/A.java",
		},
		{
			name: "neither prototype nor locus (NOT-IN-SOURCE)",
			flaw: Flaw{IssueID: "42"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, synthesizeFlawCode(tt.flaw))
		})
	}
}

// Static CWE requirement carries a synthesized source-context code string built
// from functionprototype + sourcefilepath/sourcefile:line.
func TestConvertVeracodeToHDF_StaticFlawCode(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	var cweControl *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "18" {
			cweControl = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, cweControl, "expected CWE control 18")
	require.NotNil(t, cweControl.Code, "static CWE requirement should carry synthesized code")
	assert.Contains(t, *cweControl.Code,
		"java.lang.String ping(java.lang.String) at com/veracode/verademo/controller/ToolsController.java:53")
}

// result.message maps from the flaw's nested exploitability adjustments notes
// (in document order, newline-joined), not the empty note attribute. Absence
// yields "" (NOT-IN-SOURCE) so message is omitted.
func TestFormatFlawMessage(t *testing.T) {
	withNotes := Flaw{
		ExploitabilityAdjustments: []ExploitabilityAdjustments{{
			Adjustments: []ExploitabilityAdjustment{
				{Note: "first note"},
				{Note: "second note"},
			},
		}},
	}
	assert.Equal(t, "first note\nsecond note", formatFlawMessage(withNotes))
	assert.Equal(t, "", formatFlawMessage(Flaw{}), "flaw without adjustments yields no message")
}

// End-to-end: a static flaw result carries the fixture's exploitability note as
// its message, sourced from exploitability_adjustments.exploitability_adjustment.note.
func TestConvertVeracodeToHDF_FlawMessage(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	const wantMsg = "The source of the tainted data in this web application flaw is not a web request."
	found := false
	for _, req := range result.Baselines[0].Requirements {
		for _, res := range req.Results {
			if res.Message != nil && *res.Message == wantMsg {
				found = true
			}
		}
	}
	assert.True(t, found, "expected a flaw result carrying the exploitability note as message")
}

// A CWE requirement whose flaws carry neither a prototype nor a source locus
// leaves code unset (NOT-IN-SOURCE), exercising the requirement-level guard.
func TestBuildCWERequirement_NoCode(t *testing.T) {
	cat := Category{
		CategoryID:   "99",
		CategoryName: "No Locus",
		CWEs: []CWE{{
			CWEID: "78",
			StaticFlaws: StaticFlaws{Flaws: []Flaw{
				{IssueID: "1", Severity: "5"},
			}},
		}},
	}
	req := buildCWERequirement(cat, 0.9, "")
	assert.Nil(t, req.Code, "requirement with no source-carrying flaw must leave code unset")
}

// SCA CVE requirement carries an indented-JSON serialization of the
// vulnerability/component entry that parses back to the source object.
func TestConvertVeracodeToHDF_SCACode(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	var cveControl *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "CVE-2012-5783" {
			cveControl = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, cveControl, "expected CVE control CVE-2012-5783")
	require.NotNil(t, cveControl.Code, "SCA CVE requirement should carry serialized code")

	var parsed struct {
		CVEID      string `json:"cve_id"`
		CVSSScore  string `json:"cvss_score"`
		Components []struct {
			Library   string   `json:"library"`
			FilePaths []string `json:"file_paths"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal([]byte(*cveControl.Code), &parsed),
		"code must be valid JSON that parses back to the source object")
	assert.Equal(t, "CVE-2012-5783", parsed.CVEID)
	assert.Equal(t, "5.8", parsed.CVSSScore)
	assert.NotEmpty(t, parsed.Components, "serialized entry should carry affected components")
}

// buildSCACode is byte-parity-sensitive: assert its exact indented-JSON shape,
// including the components array and file_paths, on a crafted single entry.
func TestBuildSCACode(t *testing.T) {
	vuln := Vulnerability{
		CVEID:          "CVE-2012-5783",
		CVSSScore:      "5.8",
		Severity:       "3",
		CWEID:          "CWE-20",
		FirstFoundDate: "2021-12-29 22:18:20 UTC",
		CVESummary:     "Apache Commons HttpClient does not verify hostname.",
		SeverityDesc:   "Medium",
	}
	comp := Component{
		ComponentID: "abc",
		FileName:    "commons-httpclient-3.1.jar",
		Version:     "3.1",
		Library:     "commons-httpclient",
		LibraryID:   "maven:commons-httpclient:3.1:",
		Vendor:      "commons-httpclient",
		AddedDate:   "2021-12-29 22:18:19 UTC",
		FilePaths: ComponentFilePaths{FilePath: []ComponentFilePath{
			{Value: "WEB-INF/lib/commons-httpclient-3.1.jar"},
		}},
	}
	want := `{
  "cve_id": "CVE-2012-5783",
  "cvss_score": "5.8",
  "severity": "3",
  "cwe_id": "CWE-20",
  "first_found_date": "2021-12-29 22:18:20 UTC",
  "cve_summary": "Apache Commons HttpClient does not verify hostname.",
  "severity_desc": "Medium",
  "components": [
    {
      "component_id": "abc",
      "file_name": "commons-httpclient-3.1.jar",
      "sha1": "",
      "version": "3.1",
      "library": "commons-httpclient",
      "library_id": "maven:commons-httpclient:3.1:",
      "vendor": "commons-httpclient",
      "description": "",
      "max_cvss_score": "",
      "added_date": "2021-12-29 22:18:19 UTC",
      "file_paths": [
        "WEB-INF/lib/commons-httpclient-3.1.jar"
      ]
    }
  ]
}`
	assert.Equal(t, want, buildSCACode(vuln, []Component{comp}))
}

// A component with no file paths must serialize file_paths as [] (not null),
// which is the byte the TypeScript twin's JSON.stringify emits.
func TestBuildSCACode_EmptyFilePaths(t *testing.T) {
	code := buildSCACode(Vulnerability{CVEID: "CVE-0000-0000"}, []Component{{ComponentID: "x"}})
	assert.Contains(t, code, `"file_paths": []`)
	assert.NotContains(t, code, `"file_paths": null`)
}

// SCA CVE requirements carry structured cvss[] built from the vulnerability's
// bare numeric cvss_score (no vector, version defaults to 3.1), with the derived
// severity band. The old freetext scoring lives nowhere else on the requirement.
func TestConvertVeracodeToHDF_CVSS(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	byID := func(id string) *hdf.EvaluatedRequirement {
		for i := range result.Baselines[0].Requirements {
			if result.Baselines[0].Requirements[i].ID == id {
				return &result.Baselines[0].Requirements[i]
			}
		}
		return nil
	}

	medium := byID("CVE-2012-5783")
	require.NotNil(t, medium)
	require.Len(t, medium.Cvss, 1, "CVE requirement should carry one cvss entry")
	require.NotNil(t, medium.Cvss[0].BaseScore)
	assert.InDelta(t, 5.8, *medium.Cvss[0].BaseScore, 0.0001)
	assert.Equal(t, hdf.The31, medium.Cvss[0].Version)
	require.NotNil(t, medium.Cvss[0].BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityMedium, *medium.Cvss[0].BaseSeverity)
	assert.Nil(t, medium.Cvss[0].BaseVector, "Veracode SCA carries no vector")

	high := byID("CVE-2021-42550")
	require.NotNil(t, high)
	require.Len(t, high.Cvss, 1)
	require.NotNil(t, high.Cvss[0].BaseScore)
	assert.InDelta(t, 8.5, *high.Cvss[0].BaseScore, 0.0001)
	require.NotNil(t, high.Cvss[0].BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityHigh, *high.Cvss[0].BaseSeverity)
}

// The interim tags.cve migration does not apply to Veracode: the CVE is already
// the requirement.id on SCA findings, so no duplicate tags.cve is emitted.
func TestConvertVeracodeToHDF_NoCveTag(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	for _, req := range result.Baselines[0].Requirements {
		_, hasCve := req.Tags["cve"]
		assert.False(t, hasCve, "requirement %q should not carry a tags.cve duplicate", req.ID)
	}
}

// CWE identifiers are first-class on both static (CWE) and SCA (CVE) requirements:
// static category cweid attributes are prefixed to CWE-NN; SCA vulns already carry
// the prefix. The old tags.cweid / tags.cwe freetext is gone; the NIST mapping stays.
func TestConvertVeracodeToHDF_CweFirstClass(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	byID := func(id string) *hdf.EvaluatedRequirement {
		for i := range result.Baselines[0].Requirements {
			if result.Baselines[0].Requirements[i].ID == id {
				return &result.Baselines[0].Requirements[i]
			}
		}
		return nil
	}

	static := byID("18")
	require.NotNil(t, static)
	assert.Equal(t, []string{"CWE-78"}, static.Cwe)
	_, hasCweid := static.Tags["cweid"]
	assert.False(t, hasCweid, "static requirement should not carry tags.cweid")
	assert.NotEmpty(t, static.Tags["nist"], "NIST mapping must be preserved")

	cve := byID("CVE-2012-5783")
	require.NotNil(t, cve)
	assert.Equal(t, []string{"CWE-20"}, cve.Cwe)
	_, hasCwe := cve.Tags["cwe"]
	assert.False(t, hasCwe, "CVE requirement should not carry tags.cwe")
	assert.NotEmpty(t, cve.Tags["nist"], "NIST mapping must be preserved")

	// A CVE vulnerability with an empty cwe_id emits no cwe[].
	noCwe := byID("CVE-2014-3577")
	require.NotNil(t, noCwe)
	assert.Nil(t, noCwe.Cwe, "CVE with empty cwe_id should leave cwe[] unset")
}

// buildVeracodeCvss branch coverage: score present, component fallback, both
// absent, and non-numeric — including the field-absent (no entry) paths.
func TestBuildVeracodeCvss(t *testing.T) {
	t.Run("vulnerability score present", func(t *testing.T) {
		cvss := buildVeracodeCvss(Vulnerability{CVSSScore: "7.5"}, nil)
		require.Len(t, cvss, 1)
		require.NotNil(t, cvss[0].BaseScore)
		assert.InDelta(t, 7.5, *cvss[0].BaseScore, 0.0001)
		assert.Equal(t, hdf.The31, cvss[0].Version)
	})

	t.Run("falls back to component max_cvss_score", func(t *testing.T) {
		cvss := buildVeracodeCvss(
			Vulnerability{CVSSScore: ""},
			[]Component{{MaxCVSSScore: ""}, {MaxCVSSScore: "6.4"}},
		)
		require.Len(t, cvss, 1)
		require.NotNil(t, cvss[0].BaseScore)
		assert.InDelta(t, 6.4, *cvss[0].BaseScore, 0.0001)
	})

	t.Run("no score anywhere yields no entry", func(t *testing.T) {
		assert.Nil(t, buildVeracodeCvss(Vulnerability{CVSSScore: ""}, []Component{{MaxCVSSScore: ""}}))
		assert.Nil(t, buildVeracodeCvss(Vulnerability{CVSSScore: ""}, nil))
	})

	t.Run("non-numeric score yields no entry", func(t *testing.T) {
		assert.Nil(t, buildVeracodeCvss(Vulnerability{CVSSScore: "not-a-number"}, nil))
	})
}

// A static CWE requirement carries its flaws' remediation_status as a
// requirement-level description labeled "remediation_status". In the fixture
// every flaw is "New".
func TestConvertVeracodeToHDF_RemediationStatus(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	var cweControl *hdf.EvaluatedRequirement
	for i := range result.Baselines[0].Requirements {
		if result.Baselines[0].Requirements[i].ID == "18" {
			cweControl = &result.Baselines[0].Requirements[i]
			break
		}
	}
	require.NotNil(t, cweControl, "expected CWE control 18")

	var found *hdf.Description
	for i := range cweControl.Descriptions {
		if cweControl.Descriptions[i].Label == "remediation_status" {
			found = &cweControl.Descriptions[i]
			break
		}
	}
	require.NotNil(t, found, "CWE requirement should carry a remediation_status description")
	assert.Equal(t, "New", found.Data)
}

// formatRemediationStatus branch coverage: distinct collection, and the
// absent case (no flaw carries the field) yielding "" so no description is
// emitted.
func TestFormatRemediationStatus(t *testing.T) {
	t.Run("distinct values in order", func(t *testing.T) {
		cwes := []CWE{{StaticFlaws: StaticFlaws{Flaws: []Flaw{
			{RemediationStatus: "New"},
			{RemediationStatus: "New"},
			{RemediationStatus: "Fixed"},
		}}}}
		assert.Equal(t, "New\nFixed", formatRemediationStatus(cwes))
	})

	t.Run("absent yields empty", func(t *testing.T) {
		cwes := []CWE{{StaticFlaws: StaticFlaws{Flaws: []Flaw{{IssueID: "1"}}}}}
		assert.Empty(t, formatRemediationStatus(cwes))
	})
}

// A CWE requirement whose flaws carry no remediation_status emits no
// remediation_status description (the absent branch).
func TestBuildCWERequirement_NoRemediationStatus(t *testing.T) {
	cat := Category{
		CategoryID:   "99",
		CategoryName: "No Status",
		CWEs: []CWE{{
			CWEID:       "78",
			StaticFlaws: StaticFlaws{Flaws: []Flaw{{IssueID: "1", Severity: "5"}}},
		}},
	}
	req := buildCWERequirement(cat, 0.9, "")
	for _, d := range req.Descriptions {
		assert.NotEqual(t, "remediation_status", d.Label,
			"requirement with no remediation_status flaw must not emit the description")
	}
}

// A static CWE requirement promotes its first flaw's source-file:line into the
// structured sourceLocation. Category 18 (CWE-78) first flaw is
// ToolsController.java:53. Ref remains the newline-joined source files.
func TestConvertVeracodeToHDF_SourceLocation(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	byID := func(id string) *hdf.EvaluatedRequirement {
		for i := range result.Baselines[0].Requirements {
			if result.Baselines[0].Requirements[i].ID == id {
				return &result.Baselines[0].Requirements[i]
			}
		}
		return nil
	}

	// CWE (static) branch: ref + line both present.
	cwe := byID("18")
	require.NotNil(t, cwe)
	require.NotNil(t, cwe.SourceLocation, "static CWE requirement should carry sourceLocation")
	require.NotNil(t, cwe.SourceLocation.Ref)
	assert.Equal(t, "ToolsController.java\nToolsController.java", *cwe.SourceLocation.Ref)
	require.NotNil(t, cwe.SourceLocation.Line, "static flaw line should be promoted")
	assert.Equal(t, float64(53), *cwe.SourceLocation.Line)

	// SCA (CVE) branch: ref present, line absent (SCA vulns carry no line).
	cve := byID("CVE-2012-5783")
	require.NotNil(t, cve)
	require.NotNil(t, cve.SourceLocation, "SCA CVE requirement should carry sourceLocation ref")
	require.NotNil(t, cve.SourceLocation.Ref)
	assert.Nil(t, cve.SourceLocation.Line, "SCA CVE requirement must not carry a line")
}

// firstFlawLine branch coverage: first numeric line wins, non-numeric/empty are
// skipped, and no numeric line anywhere yields nil (the absent branch).
func TestFirstFlawLine(t *testing.T) {
	t.Run("first numeric line across flaws", func(t *testing.T) {
		cwes := []CWE{{StaticFlaws: StaticFlaws{Flaws: []Flaw{
			{Line: ""},
			{Line: "83"},
			{Line: "53"},
		}}}}
		got := firstFlawLine(cwes)
		require.NotNil(t, got)
		assert.Equal(t, float64(83), *got)
	})

	t.Run("skips non-numeric lines", func(t *testing.T) {
		cwes := []CWE{{StaticFlaws: StaticFlaws{Flaws: []Flaw{
			{Line: "n/a"},
			{Line: "40"},
		}}}}
		got := firstFlawLine(cwes)
		require.NotNil(t, got)
		assert.Equal(t, float64(40), *got)
	})

	t.Run("no numeric line yields nil", func(t *testing.T) {
		cwes := []CWE{{StaticFlaws: StaticFlaws{Flaws: []Flaw{{Line: ""}, {IssueID: "1"}}}}}
		assert.Nil(t, firstFlawLine(cwes))
	})
}

func TestConvertVeracodeToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "veracode.xml")
	result, err := ConvertVeracodeToHDF(input, testConverterVersion)
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
