package oscal

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func TestConvertAssessmentResultsToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertAssessmentResultsToHDF(nil, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertAssessmentResultsToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertAssessmentResultsToHDF([]byte("not json"), "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestConvertAssessmentResultsToHDF_WrongDocumentType(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/catalog-moderate-resolved.json")
	require.NoError(t, err)

	_, err = ConvertAssessmentResultsToHDF(input, "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected assessment-results document")
}

func TestConvertAssessmentResultsToHDF_FedRAMPFixture(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Should have baselines from result sets
	require.NotEmpty(t, results.Baselines, "baselines should be populated from results")

	// First baseline should have requirements from findings
	firstBaseline := results.Baselines[0]
	assert.NotEmpty(t, firstBaseline.Name)
	assert.NotEmpty(t, firstBaseline.Requirements, "requirements should be populated from findings")

	// Requirements should have NIST-notation IDs
	for _, req := range firstBaseline.Requirements {
		assert.NotEmpty(t, req.ID, "requirement ID should not be empty")
		// NIST notation uses uppercase: AC-1, AU-1, etc.
		assert.Regexp(t, `^[A-Z]{2}-\d+`, req.ID, "requirement ID should be in NIST notation")
	}

	// Generator
	assert.NotNil(t, results.Generator)
	assert.Equal(t, "oscal-assessment-results-to-hdf", results.Generator.Name)
	assert.Equal(t, "1.0.0-test", results.Generator.Version)

	// Tool
	assert.NotNil(t, results.Tool)
	assert.Equal(t, "OSCAL Assessment Results", *results.Tool.Name)

	// PlanRef from import-ap
	assert.NotNil(t, results.PlanRef, "planRef should be set from import-ap")
}

func TestConvertAssessmentResultsToHDF_StatusMapping(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, results.Baselines)
	firstBaseline := results.Baselines[0]

	// Collect all statuses
	passedCount := 0
	failedCount := 0
	for _, req := range firstBaseline.Requirements {
		for _, r := range req.Results {
			switch r.Status {
			case hdf.Passed:
				passedCount++
			case hdf.Failed:
				failedCount++
			}
		}
	}

	// The fixture has findings with "satisfied" and "not-satisfied" statuses
	assert.Greater(t, passedCount, 0, "should have passed results from 'satisfied' findings")
	assert.Greater(t, failedCount, 0, "should have failed results from 'not-satisfied' findings")
}

func TestConvertAssessmentResultsToHDF_ImpactFromRiskSeverity(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, results.Baselines)
	firstBaseline := results.Baselines[0]

	// Some requirements should have impact derived from risk severity
	hasNonDefaultImpact := false
	for _, req := range firstBaseline.Requirements {
		if req.Impact != 0.5 {
			hasNonDefaultImpact = true
			break
		}
	}
	assert.True(t, hasNonDefaultImpact, "at least one requirement should have impact derived from risk severity")
}

func TestConvertAssessmentResultsToHDF_Descriptions(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, results.Baselines)
	firstBaseline := results.Baselines[0]

	// Every requirement should have at least a "default" description
	for _, req := range firstBaseline.Requirements {
		hasDefault := false
		for _, d := range req.Descriptions {
			if d.Label == "default" {
				hasDefault = true
			}
		}
		assert.True(t, hasDefault, "requirement %s should have a 'default' description", req.ID)
	}
}

func TestConvertAssessmentResultsToHDF_MultipleResultSets(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// The FedRAMP SAR fixture has 3 result sets (2023, 2022, 2021).
	// Only 2023 has findings; 2022 and 2021 are empty template stubs
	// and should be skipped with a warning.
	assert.Equal(t, 1, len(results.Baselines), "should only include baselines with findings (empty result sets are skipped)")
	assert.NotEmpty(t, results.Baselines[0].Requirements, "baseline should have requirements from findings")
}

func TestConvertAssessmentResultsToHDF_FindingsGroupedByControlID(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, results.Baselines)
	firstBaseline := results.Baselines[0]

	// Check that AC-1 findings are grouped (multiple findings with ac-1.a.1_obj.*)
	reqMap := make(map[string]*hdf.EvaluatedRequirement)
	for i := range firstBaseline.Requirements {
		reqMap[firstBaseline.Requirements[i].ID] = &firstBaseline.Requirements[i]
	}

	ac1, ok := reqMap["AC-1"]
	if ok {
		// Multiple findings for ac-1 objectives should produce multiple results
		assert.Greater(t, len(ac1.Results), 1, "AC-1 should have multiple results from grouped findings")
	}
}

func TestConvertAssessmentResultsToHDF_ChecksumSet(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	require.NotEmpty(t, results.Baselines)
	assert.NotNil(t, results.Baselines[0].Integrity)
	assert.Equal(t, hdf.Sha256, *results.Baselines[0].Integrity.Algorithm)
	assert.NotEmpty(t, *results.Baselines[0].Integrity.Checksum)
}

func TestConvertAssessmentResultsToHDF_RoundTripJSON(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)

	// Marshal to JSON
	out, err := json.Marshal(results)
	require.NoError(t, err)

	// Unmarshal back
	var roundtrip hdf.HDFResults
	err = json.Unmarshal(out, &roundtrip)
	require.NoError(t, err)

	assert.Equal(t, len(results.Baselines), len(roundtrip.Baselines))
	assert.Equal(t, results.Generator.Name, roundtrip.Generator.Name)
	assert.Equal(t, results.Generator.Version, roundtrip.Generator.Version)
}

func TestSarRequirementID(t *testing.T) {
	const foreignNS = "https://example.org/ns/oscal"
	tests := []struct {
		name     string
		targetID string
		props    []Property
		expected string
	}{
		{"objective groups under its control", "ac-1.a.1_obj.1", nil, "AC-1"},
		{"statement groups under its control", "au-1_smt.a", nil, "AU-1"},
		{"enhancement statement", "cm-2.1_smt.c", nil, "CM-2 (1)"},
		{"enhancement objective", "ca-8.1_obj", nil, "CA-8 (1)"},
		{"whole control", "ac-2.3", nil, "AC-2 (3)"},
		{"STIG rule id is verbatim", "sv-230221r858734_rule", nil, "sv-230221r858734_rule"},
		{"uppercase rule id is verbatim", "SV-230221r858734_rule", nil, "SV-230221r858734_rule"},
		{"uppercase look-alike of an unknown family is verbatim", "SV-230221", nil, "SV-230221"},
		{"uppercase control groups", "AC-1", nil, "AC-1"},
		{"uppercase objective groups under its control", "AC-2.3_OBJ.A", nil, "AC-2 (3)"},
		{"mixed-case part groups under its control", "ac-1.A_obj", nil, "AC-1"},
		{"zero-padded control groups canonically", "ac-01_obj.a", nil, "AC-1"},
		{"zero-padded enhancement groups canonically", "ac-02.03_obj", nil, "AC-2 (3)"},
		{"empty part after the suffix is verbatim", "ac-1_obj.", nil, "ac-1_obj."},
		{"XCCDF rule id is verbatim", "xccdf_org.ssgproject.content_rule_accounts_tmout", nil, "xccdf_org.ssgproject.content_rule_accounts_tmout"},
		{"unconfirmed control is verbatim", "zz-9_obj.1", nil, "zz-9_obj.1"},
		{"HDF prop wins over a NIST target", "ac-1", []Property{{Name: "hdf-requirement-id", Ns: hdfNS, Value: "SV-1"}}, "SV-1"},
		{"HDF prop keeps a statement id", "ac-8_smt.c.1", []Property{{Name: "hdf-requirement-id", Ns: hdfNS, Value: "AC-8 c 1"}}, "AC-8 c 1"},
		{"HDF prop remarks hold the exact id", "line_one_line_two", []Property{{Name: "hdf-requirement-id", Ns: hdfNS, Value: "line one line two", Remarks: "line one\nline two"}}, "line one\nline two"},
		{"pre-ADR prop without ns is read", "sv-1", []Property{{Name: "hdf-requirement-id", Value: "SV-1"}}, "SV-1"},
		{"foreign-namespace prop is not HDF's", "ac-1", []Property{{Name: "hdf-requirement-id", Ns: foreignNS, Value: "SV-1"}}, "AC-1"},
		{"empty HDF prop falls back to the target", "ac-1", []Property{{Name: "hdf-requirement-id", Ns: hdfNS}}, "AC-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{Props: tt.props, Target: FindingTarget{TargetID: tt.targetID}}
			id, ok := sarRequirementID(f)
			assert.True(t, ok)
			assert.Equal(t, tt.expected, id)
		})
	}

	t.Run("empty target-id has no requirement id", func(t *testing.T) {
		f := &Finding{Props: []Property{{Name: "hdf-requirement-id", Ns: hdfNS, Value: "SV-1"}}}
		id, ok := sarRequirementID(f)
		assert.False(t, ok)
		assert.Empty(t, id)
	})
}

// sarFindings builds a one-result SAR whose findings target the given ids, each
// with its own uuid and title, and no observations or risks.
func sarFindings(targetIDs ...string) []byte {
	findings := make([]string, 0, len(targetIDs))
	for i, id := range targetIDs {
		n := strconv.Itoa(i + 1)
		findings = append(findings, `{"uuid":"f`+n+`","title":"Finding `+n+`","description":"d","target":{"type":"objective-id","target-id":"`+id+`","status":{"state":"satisfied"}}}`)
	}
	return sarWithProse("["+strings.Join(findings, ",")+"]", `[]`, `[]`)
}

// requirementIDs lists a baseline's requirement ids with their result counts.
func requirementIDs(b *hdf.EvaluatedBaseline) map[string]int {
	ids := make(map[string]int, len(b.Requirements))
	for i := range b.Requirements {
		ids[b.Requirements[i].ID] = len(b.Requirements[i].Results)
	}
	return ids
}

// Foreign targets group only under roster-confirmed NIST controls; every other
// target is its own requirement, verbatim, and never merges with a look-alike.
func TestConvertAssessmentResultsToHDF_ForeignTargetsGroupOnlyUnderConfirmedControls(t *testing.T) {
	input := sarFindings(
		"sv-230221r858734_rule",
		"ac-2.3_obj.a",
		"sv-230221r991589_rule",
		"xccdf_org.ssgproject.content_rule_accounts_tmout",
		"ac-2.3_smt.b",
		"xccdf_org.ssgproject.content_rule_audit_rules_login_events",
		"au-1_smt.a",
		"zz-9_obj.1",
		"zz-9_obj.2",
		"ac-2.3",
	)
	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0")
	require.NoError(t, err)
	require.Len(t, results.Baselines, 1)
	b := &results.Baselines[0]

	order := make([]string, 0, len(b.Requirements))
	for i := range b.Requirements {
		order = append(order, b.Requirements[i].ID)
	}
	assert.Equal(t, []string{
		"sv-230221r858734_rule",
		"AC-2 (3)",
		"sv-230221r991589_rule",
		"xccdf_org.ssgproject.content_rule_accounts_tmout",
		"xccdf_org.ssgproject.content_rule_audit_rules_login_events",
		"AU-1",
		"zz-9_obj.1",
		"zz-9_obj.2",
	}, order)
	assert.Equal(t, 3, requirementIDs(b)["AC-2 (3)"])

	ac23 := findReqByID(b, "AC-2 (3)")
	assert.Equal(t, []interface{}{"AC-2 (3)"}, ac23.Tags["nist"])
	sv := findReqByID(b, "sv-230221r858734_rule")
	assert.Equal(t, []interface{}{}, sv.Tags["nist"], "an unconfirmed target names no NIST control")
	assert.Nil(t, sv.ControlType)
	assert.Equal(t, "Finding 1", *sv.Title)

	expected, _, err := ExpectedAssessmentResultsRequirementCount(input)
	require.NoError(t, err)
	assert.Equal(t, len(b.Requirements), expected)
}

// Grouping ignores letter case: a target groups with its lowercase form, while
// look-alikes NIST does not define stay verbatim and apart.
func TestConvertAssessmentResultsToHDF_TargetCaseIgnoredForGrouping(t *testing.T) {
	input := sarFindings("ac-2.3_obj.a", "AC-2.3_OBJ.B", "Ac-2.3", "SV-230221r858734_rule", "SV-230221", "sv-230221", "ac-1.A_obj")
	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0")
	require.NoError(t, err)
	require.Len(t, results.Baselines, 1)
	b := &results.Baselines[0]
	order := make([]string, 0, len(b.Requirements))
	for i := range b.Requirements {
		order = append(order, b.Requirements[i].ID)
	}
	assert.Equal(t, []string{"AC-2 (3)", "SV-230221r858734_rule", "SV-230221", "sv-230221", "AC-1"}, order)
	assert.Equal(t, 3, requirementIDs(b)["AC-2 (3)"])
	assert.Equal(t, []interface{}{"AC-2 (3)"}, findReqByID(b, "AC-2 (3)").Tags["nist"])
}

// A zero-padded target names the same control as its unpadded form, so both
// group under the one canonical requirement and NIST tag.
func TestConvertAssessmentResultsToHDF_PaddedControlGroupsCanonically(t *testing.T) {
	results, err := ConvertAssessmentResultsToHDF(sarFindings("ac-01_obj.a", "ac-1_obj.b", "ac-02.03_obj", "ac-2.3"), "1.0.0")
	require.NoError(t, err)
	require.Len(t, results.Baselines, 1)
	b := &results.Baselines[0]
	assert.Equal(t, map[string]int{"AC-1": 2, "AC-2 (3)": 2}, requirementIDs(b))
	assert.Equal(t, "AC-1", b.Requirements[0].ID)
	assert.Equal(t, []interface{}{"AC-1"}, findReqByID(b, "AC-1").Tags["nist"])
	assert.Equal(t, []interface{}{"AC-2 (3)"}, findReqByID(b, "AC-2 (3)").Tags["nist"])
}

// Warnings quote titles literally, as the TypeScript converter does, so both
// languages print identical text for a title containing a double quote.
func TestConvertAssessmentResultsToHDF_WarningsQuoteLiterally(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	input := []byte(`{"assessment-results":{
		"uuid":"11111111-1111-4111-8111-111111111111",
		"metadata":{"title":"t","last-modified":"2026-01-01T00:00:00Z","version":"1","oscal-version":"1.1.2"},
		"import-ap":{"href":"#"},
		"results":[
			{"uuid":"33333333-3333-4333-8333-333333333333","title":"Q3 \"annual\" review","description":"d","start":"2026-01-01T00:00:00Z",
			 "reviewed-controls":{"control-selections":[{"include-all":{}}]}},
			{"uuid":"44444444-4444-4444-8444-444444444444","title":"Q4 \"final\" review","description":"d","start":"2026-01-01T00:00:00Z",
			 "reviewed-controls":{"control-selections":[{"include-all":{}}]},
			 "findings":[{"uuid":"f1","title":"say \"hi\"","description":"d","target":{"type":"objective-id","target-id":"","status":{"state":"satisfied"}}}]}
		]}}`)
	_, err := ConvertAssessmentResultsToHDF(input, "1.0.0")
	require.NoError(t, err)
	assert.Contains(t, logs.String(), `WARNING: Skipping assessment result "Q3 "annual" review": no findings (empty result set)`)
	assert.Contains(t, logs.String(), `WARNING: Skipping finding "f1" titled "say "hi"": empty target-id`)
	assert.Contains(t, logs.String(), `WARNING: Skipping assessment result "Q4 "final" review": no finding has a target-id`)
}

// Findings beyond the cap are dropped. The CLI counts the expected requirements
// and then converts, so the count applies the cap silently and the conversion
// warns once; the TypeScript converter prints the same text and converts the
// same findings.
func TestConvertAssessmentResultsToHDF_FindingCap(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	const findingCap = 100000
	findings := make([]string, 0, findingCap+1)
	for i := 0; i < findingCap; i++ {
		findings = append(findings, `{"uuid":"f","title":"t","description":"d","target":{"type":"objective-id","target-id":"ac-1","status":{"state":"satisfied"}}}`)
	}
	findings = append(findings, `{"uuid":"over","title":"t","description":"d","target":{"type":"objective-id","target-id":"sv-1","status":{"state":"satisfied"}}}`)
	input := sarWithProse("["+strings.Join(findings, ",")+"]", `[]`, `[]`)

	expected, _, err := ExpectedAssessmentResultsRequirementCount(input)
	require.NoError(t, err)
	assert.Equal(t, 1, expected)
	assert.Empty(t, logs.String(), "counting must not warn")

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0")
	require.NoError(t, err)
	require.Len(t, results.Baselines, 1)
	assert.Equal(t, map[string]int{"AC-1": findingCap}, requirementIDs(&results.Baselines[0]))
	const warning = "WARNING: Input truncated at 100000 finding items (original: 100001)"
	assert.Contains(t, logs.String(), warning)
	assert.Equal(t, 1, strings.Count(logs.String(), "Input truncated at"), "count and conversion together warn exactly once")
}

// HDF-produced findings carry their requirement id in the HDF prop; findings
// with the same id are one requirement, and the prop outranks the target.
func TestConvertAssessmentResultsToHDF_HDFRequirementIDProp(t *testing.T) {
	prop := func(id string) string {
		return `"props":[{"name":"hdf-requirement-id","ns":"` + hdfNS + `","value":"` + id + `"}]`
	}
	input := sarWithProse(`[
		{"uuid":"f1","title":"t1","description":"d",`+prop("SV-230221r858734_rule")+`,"target":{"type":"objective-id","target-id":"sv-230221r858734_rule","status":{"state":"not-satisfied"}}},
		{"uuid":"f2","title":"t2","description":"d",`+prop("AC-8 c 1")+`,"target":{"type":"statement-id","target-id":"ac-8_smt.c.1","status":{"state":"satisfied"}}},
		{"uuid":"f3","title":"t3","description":"d",`+prop("SV-230221r858734_rule")+`,"target":{"type":"objective-id","target-id":"sv-230221r858734_rule","status":{"state":"satisfied"}}},
		{"uuid":"f4","title":"","description":"d","target":{"type":"objective-id","target-id":"ac-8.a_obj.1","status":{"state":"satisfied"}}}
	]`, `[]`, `[]`)
	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0")
	require.NoError(t, err)
	require.Len(t, results.Baselines, 1)
	b := &results.Baselines[0]
	assert.Equal(t, map[string]int{"SV-230221r858734_rule": 2, "AC-8 c 1": 1, "AC-8": 1}, requirementIDs(b))
	assert.Equal(t, "SV-230221r858734_rule", b.Requirements[0].ID)
	assert.Equal(t, []interface{}{"AC-8"}, findReqByID(b, "AC-8 c 1").Tags["nist"])
	assert.Equal(t, "AC-8", *findReqByID(b, "AC-8").Title, "an untitled finding is titled by its requirement id")
}

// A finding with an empty target-id is invalid OSCAL: it is skipped with a
// warning naming it, and no requirement is named "unknown". A result left with
// no usable finding yields no baseline.
func TestConvertAssessmentResultsToHDF_EmptyTargetSkippedWithWarning(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	input := sarFindings("", "ac-1", "")
	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0")
	require.NoError(t, err)
	require.Len(t, results.Baselines, 1)
	assert.Equal(t, map[string]int{"AC-1": 1}, requirementIDs(&results.Baselines[0]))
	assert.Contains(t, logs.String(), `WARNING: Skipping finding "f1" titled "Finding 1": empty target-id`)
	assert.Contains(t, logs.String(), `WARNING: Skipping finding "f3" titled "Finding 3": empty target-id`)
	assert.NotContains(t, logs.String(), `"f2"`)

	expected, _, err := ExpectedAssessmentResultsRequirementCount(input)
	require.NoError(t, err)
	assert.Equal(t, 1, expected)

	logs.Reset()
	onlyEmpty := sarFindings("")
	results, err = ConvertAssessmentResultsToHDF(onlyEmpty, "1.0.0")
	require.NoError(t, err)
	assert.Empty(t, results.Baselines)
	assert.Contains(t, logs.String(), `WARNING: Skipping finding "f1" titled "Finding 1": empty target-id`)
	assert.Contains(t, logs.String(), `WARNING: Skipping assessment result "r": no finding has a target-id`)
	expected, _, err = ExpectedAssessmentResultsRequirementCount(onlyEmpty)
	require.NoError(t, err)
	assert.Equal(t, 0, expected)
}

func TestSarBaselineName(t *testing.T) {
	tests := []struct {
		resultTitle string
		sarTitle    string
		expected    string
	}{
		{"2023 Annual Assessment", "", "2023-annual-assessment"},
		{"", "FedRAMP SAR", "fedramp-sar"},
		{"", "", "oscal-assessment-results"},
	}

	for _, tt := range tests {
		t.Run(tt.resultTitle+"/"+tt.sarTitle, func(t *testing.T) {
			result := &Result{Title: tt.resultTitle}
			sar := &AssessmentResults{Metadata: Metadata{Title: tt.sarTitle}}
			assert.Equal(t, tt.expected, sarBaselineName(result, sar))
		})
	}
}

// findReqByID returns the requirement with the given ID from the first
// baseline, or nil if absent.
func findReqByID(baseline *hdf.EvaluatedBaseline, id string) *hdf.EvaluatedRequirement {
	for i := range baseline.Requirements {
		if baseline.Requirements[i].ID == id {
			return &baseline.Requirements[i]
		}
	}
	return nil
}

// descByLabel returns the data of the first description with the given label,
// and whether such a description exists.
func descByLabel(req *hdf.EvaluatedRequirement, label string) (string, bool) {
	for _, d := range req.Descriptions {
		if d.Label == label {
			return d.Data, true
		}
	}
	return "", false
}

func TestConvertAssessmentResultsToHDF_StatementAndRemediation(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)
	require.NotEmpty(t, results.Baselines)
	baseline := &results.Baselines[0]

	// AC-1 findings relate to a risk carrying a statement and one remediation.
	ac1 := findReqByID(baseline, "AC-1")
	require.NotNil(t, ac1, "AC-1 requirement should exist")

	statement, ok := descByLabel(ac1, "statement")
	require.True(t, ok, "AC-1 should carry a 'statement' description")
	assert.Equal(t,
		"This is a statement about the identified risk.\n\nTCW: Risk Statement..\n\nScans: N/A.\n\nPen Risk Statement.\n\nRET: Risk Statement.",
		statement)

	remediation, ok := descByLabel(ac1, "remediation")
	require.True(t, ok, "AC-1 should carry a 'remediation' description")
	assert.True(t, strings.HasPrefix(remediation, "Remediation Title: A description of the recommended remediation."),
		"remediation should render as 'title: description', got %q", remediation)
}

func TestConvertAssessmentResultsToHDF_MultipleRemediationsJoined(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)
	require.NotEmpty(t, results.Baselines)
	baseline := &results.Baselines[0]

	// CM-2.1's related risk carries two remediations (tool + assessor).
	cm21 := findReqByID(baseline, "CM-2 (1)")
	require.NotNil(t, cm21, "CM-2 (1) requirement should exist")

	remediation, ok := descByLabel(cm21, "remediation")
	require.True(t, ok, "CM-2 (1) should carry a 'remediation' description")
	assert.Contains(t, remediation, "Tool's Recommendation: A description of the recommended remediation as provided by the tool.")
	assert.Contains(t, remediation, "Assessor's Recommendation: A description of the recommended remediation as provided by the assessor.")
	assert.Contains(t, remediation, "\n\n", "multiple remediations should be blank-line separated")
}

func TestConvertAssessmentResultsToHDF_EvidenceDescriptionsAndRefs(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)
	require.NotEmpty(t, results.Baselines)
	baseline := &results.Baselines[0]

	// CM-2.1's observations carry relevant-evidence with prose and a resolvable
	// vendor URL (plus a duplicate URL that must be deduplicated).
	cm21 := findReqByID(baseline, "CM-2 (1)")
	require.NotNil(t, cm21, "CM-2 (1) requirement should exist")

	evidence, ok := descByLabel(cm21, "evidence")
	require.True(t, ok, "CM-2 (1) should carry an 'evidence' description")
	assert.Contains(t, evidence, "A screen shot showing the system impact when patch is applied.")
	assert.Contains(t, evidence, "Vendor detail describing why this happens.")

	require.Len(t, cm21.Refs, 1, "duplicate evidence URLs should collapse to a single ref")
	require.NotNil(t, cm21.Refs[0].URL)
	assert.Equal(t, "https://vendor.site/article/describing/something.htm", *cm21.Refs[0].URL)
	assert.Nil(t, cm21.Refs[0].Ref)
	assert.Nil(t, cm21.Refs[0].URI)

	// AC-1's evidence hrefs are intra-document fragments only → no refs, but the
	// evidence prose is still captured.
	ac1 := findReqByID(baseline, "AC-1")
	require.NotNil(t, ac1)
	_, hasEvidence := descByLabel(ac1, "evidence")
	assert.True(t, hasEvidence, "AC-1 should still carry evidence prose from fragment-only observations")
	assert.Nil(t, ac1.Refs, "AC-1 has only fragment hrefs → no external refs")
}

func TestConvertAssessmentResultsToHDF_AbsentRiskAndEvidenceBranches(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)
	require.NotEmpty(t, results.Baselines)
	baseline := &results.Baselines[0]

	// AU-1 relates to no risk and to an observation with no relevant-evidence.
	au1 := findReqByID(baseline, "AU-1")
	require.NotNil(t, au1, "AU-1 requirement should exist")

	_, hasStatement := descByLabel(au1, "statement")
	assert.False(t, hasStatement, "AU-1 should not carry a statement (no related risk)")
	_, hasRemediation := descByLabel(au1, "remediation")
	assert.False(t, hasRemediation, "AU-1 should not carry a remediation (no related risk)")
	_, hasEvidence := descByLabel(au1, "evidence")
	assert.False(t, hasEvidence, "AU-1 should not carry evidence (observation has none)")
	assert.Nil(t, au1.Refs, "AU-1 should carry no refs")
}

func TestConvertAssessmentResultsToHDF_CCITagsFromNIST(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)
	require.NotEmpty(t, results.Baselines)
	baseline := &results.Baselines[0]

	// RA-5 maps to a CCI via the standard NIST→CCI table, so tags.cci should
	// carry it alongside the existing tags.nist.
	ra5 := findReqByID(baseline, "RA-5")
	require.NotNil(t, ra5, "RA-5 requirement should exist")
	assert.Equal(t, []interface{}{"RA-5"}, ra5.Tags["nist"], "tags.nist must be preserved")
	cci, ok := ra5.Tags["cci"].([]interface{})
	require.True(t, ok, "RA-5 should carry a tags.cci slice")
	assert.Contains(t, cci, "CCI-001643", "RA-5 should map to CCI-001643")

	// AC-1 has no NIST→CCI mapping, so tags.cci must be absent (nist preserved).
	ac1 := findReqByID(baseline, "AC-1")
	require.NotNil(t, ac1, "AC-1 requirement should exist")
	assert.Equal(t, []interface{}{"AC-1"}, ac1.Tags["nist"], "tags.nist must be preserved")
	_, hasCCI := ac1.Tags["cci"]
	assert.False(t, hasCCI, "AC-1 should not carry a tags.cci (no NIST→CCI mapping)")
}

// startTimeOfReq returns the startTime of the first result on the requirement
// with the given ID (RFC3339, trimmed-UTC as serialized).
func startTimeOfReq(baseline *hdf.EvaluatedBaseline, id string) (string, bool) {
	req := findReqByID(baseline, id)
	if req == nil || len(req.Results) == 0 {
		return "", false
	}
	return req.Results[0].StartTime.UTC().Format("2006-01-02T15:04:05Z"), true
}

func TestConvertAssessmentResultsToHDF_StartTimeFromObservationCollected(t *testing.T) {
	input, err := os.ReadFile("../fixtures/input/sar-fedramp.json")
	require.NoError(t, err)

	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0-test")
	require.NoError(t, err)
	require.NotEmpty(t, results.Baselines)
	baseline := &results.Baselines[0]

	// Every finding correlates to observations whose `collected` is
	// 2023-05-10T00:00:00Z; startTime must be the observation collected time,
	// NOT the result's assessment-period start (2023-03-01T00:00:00Z).
	for _, id := range []string{"AC-1", "AU-1", "RA-5", "CM-2 (1)", "AT-2", "CA-8 (1)"} {
		st, ok := startTimeOfReq(baseline, id)
		require.True(t, ok, "%s should have a result with a startTime", id)
		assert.Equal(t, "2023-05-10T00:00:00Z", st,
			"%s startTime should be the correlated observation `collected` time", id)
	}
}

func TestFindingStartTime(t *testing.T) {
	obsMap := map[string]*Observation{
		"early": {UUID: "early", Collected: "2023-05-10T00:00:00Z"},
		"late":  {UUID: "late", Collected: "2023-05-10T03:00:00Z"},
		"blank": {UUID: "blank", Collected: ""},
		"bad":   {UUID: "bad", Collected: "not-a-time"},
	}
	relObs := func(uuids ...string) *Finding {
		f := &Finding{}
		for _, u := range uuids {
			f.RelatedObservations = append(f.RelatedObservations, RelatedRef{ObservationUUID: u})
		}
		return f
	}

	// Single collected observation → its time.
	got := findingStartTime(relObs("early"), obsMap)
	assert.Equal(t, "2023-05-10T00:00:00Z", got.UTC().Format("2006-01-02T15:04:05Z"))

	// Multiple observations → earliest collected wins (order-independent).
	got = findingStartTime(relObs("late", "early"), obsMap)
	assert.Equal(t, "2023-05-10T00:00:00Z", got.UTC().Format("2006-01-02T15:04:05Z"))

	// Empty/unparseable collected values are skipped → zero time.
	assert.True(t, findingStartTime(relObs("blank", "bad"), obsMap).IsZero())

	// Missing observation reference → zero time.
	assert.True(t, findingStartTime(relObs("nope"), obsMap).IsZero())

	// No related observations → zero time.
	assert.True(t, findingStartTime(relObs(), obsMap).IsZero())
}

func TestFindingStartTime_FallbackChain(t *testing.T) {
	scanTime := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
	fmtT := func(tm time.Time) string { return tm.UTC().Format("2006-01-02T15:04:05Z") }

	obsMap := map[string]*Observation{
		"c": {UUID: "c", Collected: "2023-05-10T00:00:00Z"},
		"x": {UUID: "x", Collected: ""},
	}

	// Observation collected present → used directly.
	f := &Finding{RelatedObservations: []RelatedRef{{ObservationUUID: "c"}}}
	res := &Result{Start: "2020-01-01T00:00:00Z"}
	rr := findingToRequirementResult(f, obsMap, map[string]*Risk{}, res, scanTime)
	assert.Equal(t, "2023-05-10T00:00:00Z", fmtT(rr.StartTime))

	// No usable collected but result.Start present → result.Start.
	f = &Finding{RelatedObservations: []RelatedRef{{ObservationUUID: "x"}}}
	rr = findingToRequirementResult(f, obsMap, map[string]*Risk{}, res, scanTime)
	assert.Equal(t, "2020-01-01T00:00:00Z", fmtT(rr.StartTime))

	// Neither collected nor result.Start → conversion-time fallback (scanTime).
	res = &Result{}
	rr = findingToRequirementResult(f, obsMap, map[string]*Risk{}, res, scanTime)
	assert.Equal(t, fmtT(scanTime), fmtT(rr.StartTime))
	assert.False(t, rr.StartTime.IsZero(), "startTime must never be the zero value")
}

// sarWithProse builds a one-result SAR whose findings, observations and risks
// are supplied as raw JSON, so each test states exactly the prose homes it reads.
func sarWithProse(findings, observations, risks string) []byte {
	return []byte(`{"assessment-results":{
		"uuid":"11111111-1111-4111-8111-111111111111",
		"metadata":{"title":"t","last-modified":"2026-01-01T00:00:00Z","version":"1","oscal-version":"1.1.2"},
		"import-ap":{"href":"#"},
		"results":[{"uuid":"22222222-2222-4222-8222-222222222222","title":"r","description":"d","start":"2026-01-01T00:00:00Z",
			"reviewed-controls":{"control-selections":[{"include-all":{}}]},
			"findings":` + findings + `,
			"observations":` + observations + `,
			"risks":` + risks + `}]}}`)
}

func convertSingleRequirement(t *testing.T, input []byte) *hdf.EvaluatedRequirement {
	t.Helper()
	results, err := ConvertAssessmentResultsToHDF(input, "1.0.0")
	require.NoError(t, err)
	require.Len(t, results.Baselines, 1)
	require.Len(t, results.Baselines[0].Requirements, 1)
	return &results.Baselines[0].Requirements[0]
}

const hdfNS = "https://mitre.github.io/hdf-libs/ns/oscal"

func TestDescriptionLabelHelpers(t *testing.T) {
	assert.Equal(t, Property{Name: "description-label", Ns: hdfNS, Value: "check"}, DescriptionLabelProp("check"))

	assert.Equal(t, "fix", DescriptionLabel([]Property{{Name: "other", Ns: hdfNS, Value: "x"}, DescriptionLabelProp("fix")}))
	assert.Empty(t, DescriptionLabel([]Property{{Name: "description-label", Value: "fix"}}), "no ns is foreign")
	assert.Empty(t, DescriptionLabel([]Property{{Name: "description-label", Ns: "https://example.org/ns/oscal", Value: "fix"}}))
	assert.Empty(t, DescriptionLabel(nil))

	assert.PanicsWithValue(t, `oscal: description label "" yields no description-label prop`, func() { DescriptionLabelProp("") })
}

// Rationale is read from finding.target.description; observation descriptions
// are no longer read as rationale.
func TestConvertAssessmentResultsToHDF_RationaleFromTargetDescription(t *testing.T) {
	input := sarWithProse(`[
		{"uuid":"f1","title":"t","description":"d1","target":{"type":"objective-id","target-id":"ac-1","description":"first\nconclusion\n","status":{"state":"satisfied"}},
		 "related-observations":[{"observation-uuid":"o1"}]},
		{"uuid":"f2","title":"t","description":"d2","target":{"type":"objective-id","target-id":"ac-1","status":{"state":"satisfied"}}},
		{"uuid":"f3","title":"t","description":"d3","target":{"type":"objective-id","target-id":"ac-1","description":"second","status":{"state":"satisfied"}}}
	]`, `[{"uuid":"o1","description":"observation prose","methods":["TEST"],"collected":"2026-01-01T00:00:00Z"}]`, `[]`)
	req := convertSingleRequirement(t, input)
	rationale, ok := descByLabel(req, "rationale")
	require.True(t, ok)
	assert.Equal(t, "first\nconclusion\n\nsecond", rationale)
}

func TestConvertAssessmentResultsToHDF_NoTargetDescriptionNoRationale(t *testing.T) {
	input := sarWithProse(`[
		{"uuid":"f1","title":"t","description":"d","target":{"type":"objective-id","target-id":"ac-1","status":{"state":"satisfied"}},
		 "related-observations":[{"observation-uuid":"o1"}]}
	]`, `[{"uuid":"o1","description":"observation prose","methods":["TEST"],"collected":"2026-01-01T00:00:00Z"}]`, `[]`)
	req := convertSingleRequirement(t, input)
	_, ok := descByLabel(req, "rationale")
	assert.False(t, ok, "observation descriptions are not rationale")
}

// Labelled evidence entries and fix remediations are HDF's own prose homes and
// return exactly; they are not echoed as evidence or remediation descriptions.
func TestConvertAssessmentResultsToHDF_LabelledProseReadBack(t *testing.T) {
	input := sarWithProse(`[
		{"uuid":"f1","title":"t","description":"d","target":{"type":"objective-id","target-id":"ac-1","status":{"state":"not-satisfied"}},
		 "related-observations":[{"observation-uuid":"o1"}],"related-risks":[{"risk-uuid":"r1"}]}
	]`, `[{"uuid":"o1","description":"o","methods":["TEST"],"collected":"2026-01-01T00:00:00Z","relevant-evidence":[
		{"description":"Check line","remarks":"Check line\n  full check\n","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"check"}]},
		{"description":"plain evidence"}
	]}]`, `[{"uuid":"r1","title":"Risk","description":"rd","statement":"rs","status":"open","remediations":[
		{"uuid":"m1","lifecycle":"recommendation","title":"Recommended fix","description":"do\nthis","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"fix"}]},
		{"uuid":"m2","lifecycle":"accepted","title":"waiver","description":"accepted"}
	]}]`)
	req := convertSingleRequirement(t, input)

	check, ok := descByLabel(req, "check")
	require.True(t, ok)
	assert.Equal(t, "Check line\n  full check\n", check)
	fix, ok := descByLabel(req, "fix")
	require.True(t, ok)
	assert.Equal(t, "do\nthis", fix)

	remediation, ok := descByLabel(req, "remediation")
	require.True(t, ok)
	assert.Equal(t, "waiver: accepted", remediation, "only the unlabelled remediation remains a remediation")
	evidence, ok := descByLabel(req, "evidence")
	require.True(t, ok)
	assert.Equal(t, "plain evidence", evidence, "only unlabelled evidence remains evidence")
}

// An impact-0 fix lives in labelled evidence; an entry without remarks yields
// its description.
func TestConvertAssessmentResultsToHDF_LabelledEvidenceFixWithoutRemarks(t *testing.T) {
	input := sarWithProse(`[
		{"uuid":"f1","title":"t","description":"d","target":{"type":"objective-id","target-id":"ac-1","status":{"state":"satisfied"}},
		 "related-observations":[{"observation-uuid":"o1"},{"observation-uuid":"o1"}]}
	]`, `[{"uuid":"o1","description":"o","methods":["TEST"],"collected":"2026-01-01T00:00:00Z","relevant-evidence":[
		{"description":"single-line fix","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"fix"}]}
	]}]`, `[]`)
	req := convertSingleRequirement(t, input)
	fix, ok := descByLabel(req, "fix")
	require.True(t, ok)
	assert.Equal(t, "single-line fix", fix)
	_, ok = descByLabel(req, "evidence")
	assert.False(t, ok)
	_, ok = descByLabel(req, "check")
	assert.False(t, ok)
}

// Foreign content — no description-label, a description-label outside the HDF
// namespace, or a label value HDF does not define — imports as it did before.
func TestConvertAssessmentResultsToHDF_ForeignProseUnlabelled(t *testing.T) {
	input := sarWithProse(`[
		{"uuid":"f1","title":"t","description":"d","target":{"type":"objective-id","target-id":"ac-1","status":{"state":"not-satisfied"}},
		 "related-observations":[{"observation-uuid":"o1"}],"related-risks":[{"risk-uuid":"r1"}]}
	]`, `[{"uuid":"o1","description":"o","methods":["TEST"],"collected":"2026-01-01T00:00:00Z","relevant-evidence":[
		{"description":"no label","remarks":"remark one"},
		{"description":"no ns","remarks":"remark two","props":[{"name":"description-label","value":"check"}]},
		{"description":"other ns","props":[{"name":"description-label","ns":"https://example.org/ns/oscal","value":"fix"}]},
		{"description":"unknown value","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"rationale"}]}
	]}]`, `[{"uuid":"r1","title":"Risk","description":"rd","statement":"rs","status":"open","remediations":[
		{"uuid":"m1","lifecycle":"recommendation","title":"Recommended fix","description":"patch it"},
		{"uuid":"m2","lifecycle":"recommendation","title":"Vendor","description":"upgrade","props":[{"name":"description-label","value":"fix"}]},
		{"uuid":"m3","lifecycle":"recommendation","title":"Checker","description":"look","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"check"}]}
	]}]`)
	req := convertSingleRequirement(t, input)

	_, ok := descByLabel(req, "check")
	assert.False(t, ok, "unlabelled evidence is never check")
	_, ok = descByLabel(req, "fix")
	assert.False(t, ok, "unlabelled remediations are never fix")

	remediation, ok := descByLabel(req, "remediation")
	require.True(t, ok)
	assert.Equal(t, "Recommended fix: patch it\n\nVendor: upgrade\n\nChecker: look", remediation)
	evidence, ok := descByLabel(req, "evidence")
	require.True(t, ok)
	assert.Equal(t, "no label\nno ns\nother ns\nunknown value", evidence)
}

// Findings merged onto one requirement contribute their labelled prose in
// finding order, each observation and risk read once.
func TestConvertAssessmentResultsToHDF_LabelledProseAcrossFindings(t *testing.T) {
	input := sarWithProse(`[
		{"uuid":"f1","title":"t","description":"d","target":{"type":"objective-id","target-id":"ac-1","status":{"state":"not-satisfied"}},
		 "related-observations":[{"observation-uuid":"o1"}],"related-risks":[{"risk-uuid":"r1"}]},
		{"uuid":"f2","title":"t","description":"d","target":{"type":"objective-id","target-id":"ac-1","status":{"state":"not-satisfied"}},
		 "related-observations":[{"observation-uuid":"o2"},{"observation-uuid":"o1"},{"observation-uuid":"missing"}],"related-risks":[{"risk-uuid":"r1"},{"risk-uuid":"r2"},{"risk-uuid":"missing"}]}
	]`, `[
		{"uuid":"o1","description":"o","methods":["TEST"],"collected":"2026-01-01T00:00:00Z","relevant-evidence":[
			{"description":"c1","remarks":"check one","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"check"}]}]},
		{"uuid":"o2","description":"o","methods":["TEST"],"collected":"2026-01-01T00:00:00Z","relevant-evidence":[
			{"description":"c2","remarks":"check two","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"check"}]},
			{"description":"f2","remarks":"fix two","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"fix"}]}]}
	]`, `[{"uuid":"r1","title":"Risk","description":"rd","statement":"rs","status":"open","remediations":[
		{"uuid":"m1","lifecycle":"recommendation","title":"Recommended fix","description":"fix one","props":[{"name":"description-label","ns":"`+hdfNS+`","value":"fix"}]}
	]},{"uuid":"r2","title":"Risk","description":"rd","statement":"rs","status":"open"}]`)
	req := convertSingleRequirement(t, input)
	check, ok := descByLabel(req, "check")
	require.True(t, ok)
	assert.Equal(t, "check one\ncheck two", check)
	fix, ok := descByLabel(req, "fix")
	require.True(t, ok)
	assert.Equal(t, "fix one\nfix two", fix)
}

func TestRemediationText(t *testing.T) {
	tests := []struct {
		name     string
		rem      Remediation
		expected string
	}{
		{"title and description", Remediation{Title: "T", Description: "D"}, "T: D"},
		{"title only", Remediation{Title: "T"}, "T"},
		{"description only", Remediation{Description: "D"}, "D"},
		{"neither", Remediation{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, remediationText(&tt.rem))
		})
	}
}

func TestIsResolvableURL(t *testing.T) {
	assert.True(t, isResolvableURL("https://vendor.site/x.htm"))
	assert.True(t, isResolvableURL("http://example.com"))
	assert.False(t, isResolvableURL("#65fb91b1-f7dc-46bf-8b99-bd98f1a5293d"))
	assert.False(t, isResolvableURL(""))
	assert.False(t, isResolvableURL("relative/path"))
}

func TestMapFindingStatus(t *testing.T) {
	tests := []struct {
		state    string
		expected hdf.ResultStatus
	}{
		{"satisfied", hdf.Passed},
		{"not-satisfied", hdf.Failed},
		{"other", hdf.NotReviewed},
		{"", hdf.NotReviewed},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			f := &Finding{Target: FindingTarget{Status: TargetStatus{State: tt.state}}}
			assert.Equal(t, tt.expected, mapFindingStatus(f))
		})
	}
}
