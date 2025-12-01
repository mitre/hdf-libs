package cmd

import (
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
			name: "passed from overall_status",
			control: hdf.EvaluatedRequirement{
				OverallStatus: ptrOverallStatus(hdf.OverallStatusPassed),
				Results:       []hdf.RequirementResult{},
			},
			expected: "passed",
		},
		{
			name: "failed from overall_status",
			control: hdf.EvaluatedRequirement{
				OverallStatus: ptrOverallStatus(hdf.OverallStatusFailed),
				Results:       []hdf.RequirementResult{},
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
					{Status: ptrResultStatus(hdf.ResultStatusPassed)},
				},
			},
			expected: "passed",
		},
		{
			name: "failed from results",
			control: hdf.EvaluatedRequirement{
				Impact: 0.5,
				Results: []hdf.RequirementResult{
					{Status: ptrResultStatus(hdf.ResultStatusPassed)},
					{Status: ptrResultStatus(hdf.ResultStatusFailed)},
				},
			},
			expected: "failed",
		},
		{
			name: "error takes precedence",
			control: hdf.EvaluatedRequirement{
				Impact: 0.5,
				Results: []hdf.RequirementResult{
					{Status: ptrResultStatus(hdf.ResultStatusFailed)},
					{Status: ptrResultStatus(hdf.ResultStatusError)},
				},
			},
			expected: "error",
		},
		{
			name: "skipped from results",
			control: hdf.EvaluatedRequirement{
				Impact: 0.5,
				Results: []hdf.RequirementResult{
					{Status: ptrResultStatus(hdf.Skipped)},
				},
			},
			expected: "skipped",
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

// Helper functions to create pointers.
func ptrOverallStatus(s hdf.OverallStatus) *hdf.OverallStatus {
	return &s
}

func ptrResultStatus(s hdf.ResultStatus) *hdf.ResultStatus {
	return &s
}
