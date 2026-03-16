package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

func TestDetermineControlStatus(t *testing.T) {
	tests := []struct {
		name     string
		control  hdf.EvaluatedRequirement
		expected string
	}{
		{
			name: "passed from effective_status",
			control: hdf.EvaluatedRequirement{
				EffectiveStatus: ptrResultStatus(hdf.Passed),
				Results:         []hdf.RequirementResult{},
			},
			expected: "passed",
		},
		{
			name: "failed from effective_status",
			control: hdf.EvaluatedRequirement{
				EffectiveStatus: ptrResultStatus(hdf.Failed),
				Results:         []hdf.RequirementResult{},
			},
			expected: "failed",
		},
		{
			name: "not_applicable with zero impact and no results",
			control: hdf.EvaluatedRequirement{
				Impact:  0,
				Results: []hdf.RequirementResult{},
			},
			expected: "not_applicable",
		},
		{
			name: "not_reviewed with positive impact and no results",
			control: hdf.EvaluatedRequirement{
				Impact:  0.5,
				Results: []hdf.RequirementResult{},
			},
			expected: "not_reviewed",
		},
		{
			name: "passed from results",
			control: hdf.EvaluatedRequirement{
				Impact: 0.5,
				Results: []hdf.RequirementResult{
					{Status: ptrResultStatus(hdf.Passed)},
				},
			},
			expected: "passed",
		},
		{
			name: "failed from results",
			control: hdf.EvaluatedRequirement{
				Impact: 0.5,
				Results: []hdf.RequirementResult{
					{Status: ptrResultStatus(hdf.Passed)},
					{Status: ptrResultStatus(hdf.Failed)},
				},
			},
			expected: "failed",
		},
		{
			name: "error takes precedence",
			control: hdf.EvaluatedRequirement{
				Impact: 0.5,
				Results: []hdf.RequirementResult{
					{Status: ptrResultStatus(hdf.Failed)},
					{Status: ptrResultStatus(hdf.Error)},
				},
			},
			expected: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineControlStatus(tt.control)
			if result != tt.expected {
				t.Errorf("determineControlStatus() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper function to create pointers.
func ptrResultStatus(s hdf.ResultStatus) *hdf.ResultStatus {
	return &s
}

// writeHDFFixture writes a synthetic HDF results JSON to a temp file and returns its path.
func writeHDFFixture(t *testing.T, hdfData interface{}) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "fixture.json")
	data, err := json.Marshal(hdfData)
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	return path
}

// makeRequirementWithResultStatus builds a minimal requirement whose first result
// has the given HDF schema status (camelCase). The CLI's determineControlStatus
// maps schema NotApplicable/NotReviewed to the CLI's snake_case variants.
func makeRequirementWithResultStatus(id, resultStatus string) map[string]interface{} {
	return map[string]interface{}{
		"id":           id,
		"descriptions": []interface{}{map[string]interface{}{"label": "default", "data": "test"}},
		"impact":       0.5,
		"tags":         map[string]interface{}{},
		"results": []interface{}{
			map[string]interface{}{
				"status":    resultStatus,
				"codeDesc":  "synthetic check",
				"startTime": "2025-01-01T00:00:00Z",
			},
		},
	}
}

// syntheticHDFForStats builds a fixture with one requirement per status type.
func syntheticHDFForStats() map[string]interface{} {
	return map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "Synthetic Baseline",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "abc"},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "passed"),
					makeRequirementWithResultStatus("REQ-002", "failed"),
					makeRequirementWithResultStatus("REQ-003", "notApplicable"),
					makeRequirementWithResultStatus("REQ-004", "notReviewed"),
					makeRequirementWithResultStatus("REQ-005", "error"),
				},
			},
		},
		"targets":    []interface{}{},
		"statistics": map[string]interface{}{},
	}
}

func TestCalculateStats_AllStatuses(t *testing.T) {
	// Uses HDF v2 schema enum values (camelCase). SchemaStatusToDisplay maps
	// them to CLI snake_case constants. This tests the full pipeline:
	// schema EffectiveStatus → determineControlStatus → calculateStats counter.
	tests := []struct {
		name   string
		status hdf.ResultStatus
		field  func(controlStats) int
	}{
		{"passed", hdf.Passed, func(s controlStats) int { return s.Passed }},
		{"failed", hdf.Failed, func(s controlStats) int { return s.Failed }},
		{"not_applicable", hdf.NotApplicable, func(s controlStats) int { return s.NotApplicable }},
		{"not_reviewed", hdf.NotReviewed, func(s controlStats) int { return s.NotReviewed }},
		{"error", hdf.Error, func(s controlStats) int { return s.Error }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := hdf.EvaluatedRequirement{
				EffectiveStatus: ptrResultStatus(tt.status),
				Results:         []hdf.RequirementResult{},
			}
			results := hdf.HdfResults{
				Baselines: []hdf.EvaluatedBaseline{
					{Name: "test", Requirements: []hdf.EvaluatedRequirement{control}},
				},
			}
			stats := calculateStats(results)
			if stats.Total != 1 {
				t.Errorf("expected Total=1, got %d", stats.Total)
			}
			if tt.field(stats) != 1 {
				t.Errorf("expected %s counter=1, got %d", tt.name, tt.field(stats))
			}
		})
	}
}

func TestDetermineControlStatus_MixedPassedAndNotReviewed(t *testing.T) {
	// Regression: V-81005 has results {notReviewed, passed}. InSpec precedence:
	// passed wins over notReviewed. Old code did early return on notReviewed.
	control := hdf.EvaluatedRequirement{
		Impact: 0.7,
		Results: []hdf.RequirementResult{
			{Status: ptrResultStatus(hdf.NotReviewed)},
			{Status: ptrResultStatus(hdf.Passed)},
		},
	}
	result := determineControlStatus(control)
	if result != StatusPassed {
		t.Errorf("determineControlStatus() = %v, want %v (passed wins over notReviewed)", result, StatusPassed)
	}
}

func TestDetermineControlStatus_EffectiveStatusNotApplicable(t *testing.T) {
	// Regression: effectiveStatus=notApplicable (camelCase from v2 schema)
	// must map to "not_applicable" (snake_case CLI constant)
	control := hdf.EvaluatedRequirement{
		Impact:          0,
		EffectiveStatus: ptrResultStatus(hdf.NotApplicable),
		Results:         []hdf.RequirementResult{},
	}
	result := determineControlStatus(control)
	if result != StatusNotApplicable {
		t.Errorf("determineControlStatus() = %v, want %v", result, StatusNotApplicable)
	}
}

func TestDetermineControlStatus_EffectiveStatusNotReviewed(t *testing.T) {
	// Regression: effectiveStatus=notReviewed (camelCase) must map to "not_reviewed" (snake_case)
	control := hdf.EvaluatedRequirement{
		Impact:          0.5,
		EffectiveStatus: ptrResultStatus(hdf.NotReviewed),
		Results:         []hdf.RequirementResult{},
	}
	result := determineControlStatus(control)
	if result != StatusNotReviewed {
		t.Errorf("determineControlStatus() = %v, want %v", result, StatusNotReviewed)
	}
}

func TestStatsCommand_AllStatuses_JSON(t *testing.T) {
	// Build a fixture using schema-valid result statuses so both calculateStats
	// switch statements (lines 78–91 and 168–181) are exercised via the CLI path.
	// Uses result-level statuses (notApplicable, notReviewed) which determineControlStatus
	// maps to the CLI's snake_case variants (not_applicable, not_reviewed).
	fixtureData := syntheticHDFForStats()
	fixturePath := writeHDFFixture(t, fixtureData)

	stdout, stderr, err := executeCommand("stats", "--json", fixturePath)
	if err != nil {
		t.Fatalf("stats command failed: %v (stderr: %s)", err, stderr)
	}

	var output map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("stats output is not valid JSON: %v", err)
	}

	controls, ok := output["controls"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'controls' key in JSON output")
	}

	for _, key := range []string{"total", "passed", "failed", "not_applicable", "not_reviewed", "error"} {
		if _, exists := controls[key]; !exists {
			t.Errorf("expected key %q in controls output", key)
		}
	}
}
