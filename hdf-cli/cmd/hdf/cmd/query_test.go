package cmd

import (
	"testing"
)

func TestImpactToSeverity(t *testing.T) {
	tests := []struct {
		name     string
		impact   float64
		expected string
	}{
		{"high severity at 1.0", 1.0, "high"},
		{"high severity at 0.7", 0.7, "high"},
		{"medium severity at 0.69", 0.69, "medium"},
		{"medium severity at 0.4", 0.4, "medium"},
		{"low severity at 0.39", 0.39, "low"},
		{"low severity at 0.1", 0.1, "low"},
		{"low severity at 0.01", 0.01, "low"},
		{"none severity at 0", 0.0, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := impactToSeverity(tt.impact)
			if result != tt.expected {
				t.Errorf("impactToSeverity(%v) = %v, want %v", tt.impact, result, tt.expected)
			}
		})
	}
}

func TestParseImpactFilter(t *testing.T) {
	tests := []struct {
		name       string
		filter     string
		expectedOp string
		expectedV  float64
	}{
		{"greater than", ">0.5", ">", 0.5},
		{"greater or equal", ">=0.7", ">=", 0.7},
		{"less than", "<0.4", "<", 0.4},
		{"less or equal", "<=0.3", "<=", 0.3},
		{"equals explicit", "=0.5", "=", 0.5},
		{"equals implicit", "0.5", "=", 0.5},
		{"with spaces", "> 0.5", ">", 0.5},
		{"zero", "0", "=", 0.0},
		{"one", "1.0", "=", 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, val := parseImpactFilter(tt.filter)
			if op != tt.expectedOp {
				t.Errorf("parseImpactFilter(%q) op = %v, want %v", tt.filter, op, tt.expectedOp)
			}
			if val != tt.expectedV {
				t.Errorf("parseImpactFilter(%q) val = %v, want %v", tt.filter, val, tt.expectedV)
			}
		})
	}
}

func TestCompareImpact(t *testing.T) {
	tests := []struct {
		name     string
		impact   float64
		op       string
		val      float64
		expected bool
	}{
		{"0.7 > 0.5", 0.7, ">", 0.5, true},
		{"0.5 > 0.5", 0.5, ">", 0.5, false},
		{"0.3 > 0.5", 0.3, ">", 0.5, false},
		{"0.7 >= 0.5", 0.7, ">=", 0.5, true},
		{"0.5 >= 0.5", 0.5, ">=", 0.5, true},
		{"0.3 >= 0.5", 0.3, ">=", 0.5, false},
		{"0.3 < 0.5", 0.3, "<", 0.5, true},
		{"0.5 < 0.5", 0.5, "<", 0.5, false},
		{"0.7 < 0.5", 0.7, "<", 0.5, false},
		{"0.3 <= 0.5", 0.3, "<=", 0.5, true},
		{"0.5 <= 0.5", 0.5, "<=", 0.5, true},
		{"0.7 <= 0.5", 0.7, "<=", 0.5, false},
		{"0.5 = 0.5", 0.5, "=", 0.5, true},
		{"0.7 = 0.5", 0.7, "=", 0.5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareImpact(tt.impact, tt.op, tt.val)
			if result != tt.expected {
				t.Errorf("compareImpact(%v, %q, %v) = %v, want %v", tt.impact, tt.op, tt.val, result, tt.expected)
			}
		})
	}
}

func TestTagContains(t *testing.T) {
	tests := []struct {
		name     string
		tags     map[string]interface{}
		key      string
		value    string
		expected bool
	}{
		{
			name:     "nil tags",
			tags:     nil,
			key:      "cci",
			value:    "CCI-000366",
			expected: false,
		},
		{
			name:     "missing key",
			tags:     map[string]interface{}{"nist": "AC-2"},
			key:      "cci",
			value:    "CCI-000366",
			expected: false,
		},
		{
			name:     "string match",
			tags:     map[string]interface{}{"cci": "CCI-000366"},
			key:      "cci",
			value:    "CCI-000366",
			expected: true,
		},
		{
			name:     "string case insensitive",
			tags:     map[string]interface{}{"cci": "cci-000366"},
			key:      "cci",
			value:    "CCI-000366",
			expected: true,
		},
		{
			name:     "string no match",
			tags:     map[string]interface{}{"cci": "CCI-000367"},
			key:      "cci",
			value:    "CCI-000366",
			expected: false,
		},
		{
			name:     "array match",
			tags:     map[string]interface{}{"cci": []interface{}{"CCI-000365", "CCI-000366", "CCI-000367"}},
			key:      "cci",
			value:    "CCI-000366",
			expected: true,
		},
		{
			name:     "array no match",
			tags:     map[string]interface{}{"cci": []interface{}{"CCI-000365", "CCI-000367"}},
			key:      "cci",
			value:    "CCI-000366",
			expected: false,
		},
		{
			name:     "string array match",
			tags:     map[string]interface{}{"nist": []string{"AC-2", "CM-6"}},
			key:      "nist",
			value:    "AC-2",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tagContains(tt.tags, tt.key, tt.value)
			if result != tt.expected {
				t.Errorf("tagContains() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		name     string
		glob     string
		expected string
	}{
		{"simple", "AC-2", "^AC-2$"},
		{"asterisk", "AC-*", "^AC-.*$"},
		{"question mark", "AC-?", "^AC-.$"},
		// Note: dots are escaped with double backslash in Go strings
		{"escape dot", "test.json", "^test\\\\.json$"},
		{"multiple wildcards", "*.test.*", "^.*\\\\.test\\\\..*$"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := globToRegex(tt.glob)
			if result != tt.expected {
				t.Errorf("globToRegex(%q) = %q, want %q", tt.glob, result, tt.expected)
			}
		})
	}
}

func TestMatchesGlob(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		pattern  string
		expected bool
	}{
		{"exact match", "AC-2", "AC-2", true},
		{"no match", "AC-2", "AC-3", false},
		{"wildcard match", "AC-2", "AC-*", true},
		{"wildcard match multiple", "redhat-enterprise-linux", "redhat*", true},
		{"case insensitive", "AC-2", "ac-2", true},
		{"question mark", "AC-2", "AC-?", true},
		{"complex pattern", "profile-name-v123", "profile-*-v???", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesGlob(tt.s, tt.pattern)
			if result != tt.expected {
				t.Errorf("matchesGlob(%q, %q) = %v, want %v", tt.s, tt.pattern, result, tt.expected)
			}
		})
	}
}

func TestTagMatchesGlob(t *testing.T) {
	tests := []struct {
		name     string
		tags     map[string]interface{}
		key      string
		pattern  string
		expected bool
	}{
		{
			name:     "exact match in array",
			tags:     map[string]interface{}{"nist": []interface{}{"AC-2", "CM-6"}},
			key:      "nist",
			pattern:  "AC-2",
			expected: true,
		},
		{
			name:     "wildcard match in array",
			tags:     map[string]interface{}{"nist": []interface{}{"AC-2", "CM-6"}},
			key:      "nist",
			pattern:  "AC-*",
			expected: true,
		},
		{
			name:     "no match in array",
			tags:     map[string]interface{}{"nist": []interface{}{"AC-2", "CM-6"}},
			key:      "nist",
			pattern:  "AU-*",
			expected: false,
		},
		{
			name:     "string value match",
			tags:     map[string]interface{}{"severity": "high"},
			key:      "severity",
			pattern:  "high",
			expected: true,
		},
		{
			name:     "string value wildcard",
			tags:     map[string]interface{}{"stig_id": "RHEL-07-010010"},
			key:      "stig_id",
			pattern:  "RHEL-07-*",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tagMatchesGlob(tt.tags, tt.key, tt.pattern)
			if result != tt.expected {
				t.Errorf("tagMatchesGlob() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSeverityToLabel(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"high", "HIGH"},
		{"medium", "MED "},
		{"low", "LOW "},
		{"none", "NONE"},
		{"unknown", "NONE"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := severityToLabel(tt.severity)
			if result != tt.expected {
				t.Errorf("severityToLabel(%q) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestStatusToSymbol(t *testing.T) {
	tests := []struct {
		status   string
		expected string
	}{
		{"passed", "✓"},
		{"failed", "✗"},
		{"error", "!"},
		{"not_applicable", "○"},
		{"not_reviewed", "?"},
		{"skipped", "-"},
		{"unknown", " "},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			result := statusToSymbol(tt.status)
			if result != tt.expected {
				t.Errorf("statusToSymbol(%q) = %q, want %q", tt.status, result, tt.expected)
			}
		})
	}
}
