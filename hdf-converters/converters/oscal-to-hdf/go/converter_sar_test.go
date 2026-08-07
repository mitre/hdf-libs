package oscal

import (
	"encoding/json"
	"os"
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

func TestExtractControlIDFromFinding_ObjectiveID(t *testing.T) {
	tests := []struct {
		targetID string
		expected string
	}{
		{"ac-1.a.1_obj.1", "ac-1"},
		{"ac-1.a.1_obj.2", "ac-1"},
		{"ac-2.a_obj.1", "ac-2"},
		{"au-1_smt.a", "au-1"},
		{"ra-5_smt.a", "ra-5"},
		{"cm-2.1_smt.c", "cm-2.1"},
		{"at-2.c_obj.2", "at-2"},
		{"ca-8.1_obj", "ca-8.1"},
		{"ac-1", "ac-1"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.targetID, func(t *testing.T) {
			f := &Finding{Target: FindingTarget{TargetID: tt.targetID}}
			assert.Equal(t, tt.expected, extractControlIDFromFinding(f))
		})
	}
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
