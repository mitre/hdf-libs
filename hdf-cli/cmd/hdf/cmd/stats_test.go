package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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
					{Status: hdf.Passed},
				},
			},
			expected: "passed",
		},
		{
			name: "failed from results",
			control: hdf.EvaluatedRequirement{
				Impact: 0.5,
				Results: []hdf.RequirementResult{
					{Status: hdf.Passed},
					{Status: hdf.Failed},
				},
			},
			expected: "failed",
		},
		{
			name: "error takes precedence",
			control: hdf.EvaluatedRequirement{
				Impact: 0.5,
				Results: []hdf.RequirementResult{
					{Status: hdf.Failed},
					{Status: hdf.Error},
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
// has the given HDF schema status (camelCase).
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
