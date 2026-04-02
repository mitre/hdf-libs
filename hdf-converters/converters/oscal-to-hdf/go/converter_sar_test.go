package oscal

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-schema"
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
