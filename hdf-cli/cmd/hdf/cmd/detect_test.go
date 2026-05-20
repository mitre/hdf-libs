package cmd

import "testing"

func TestDetectHDFDocumentType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"results", `{"baselines": [], "components": [], "statistics": {}}`, "results"},
		{"baseline", `{"name": "test", "requirements": [], "supports": []}`, "baseline"},
		{"system", `{"name": "Portal", "components": []}`, "system"},
		{"plan", `{"name": "plan", "assessments": []}`, "plan"},
		{"amendments", `{"name": "waivers", "overrides": []}`, "amendments"},
		{"evidence-package", `{"name": "pkg", "contents": []}`, "evidence-package"},
		{"comparison", `{"comparisonMode": "temporal", "requirementDiffs": []}`, "comparison"},
		{"empty object", `{}`, ""},
		{"invalid JSON", `not json`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectHDFDocumentType([]byte(tc.input))
			if got != tc.expected {
				t.Errorf("detectHDFDocumentType() = %q, want %q", got, tc.expected)
			}
		})
	}
}
