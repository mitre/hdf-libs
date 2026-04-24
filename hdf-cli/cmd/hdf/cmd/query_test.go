package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

func TestImpactToSeverity(t *testing.T) {
	tests := []struct {
		name     string
		impact   float64
		expected string
	}{
		// CVSS bands normalized to 0-1: 0.9-1.0=critical, 0.7-0.8=high, 0.4-0.6=medium, 0.1-0.3=low, 0.0=informational
		{"critical severity at 1.0", 1.0, "critical"},
		{"critical severity at 0.9", 0.9, "critical"},
		{"critical severity at 0.95", 0.95, "critical"},
		{"high severity at 0.89", 0.89, "high"},
		{"high severity at 0.8", 0.8, "high"},
		{"high severity at 0.7", 0.7, "high"},
		{"medium severity at 0.69", 0.69, "medium"},
		{"medium severity at 0.5", 0.5, "medium"},
		{"medium severity at 0.4", 0.4, "medium"},
		{"low severity at 0.39", 0.39, "low"},
		{"low severity at 0.3", 0.3, "low"},
		{"low severity at 0.1", 0.1, "low"},
		{"low severity at 0.01", 0.01, "low"},
		{"informational severity at 0", 0.0, "informational"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hdfutil.ImpactToSeverity(tt.impact)
			if result != tt.expected {
				t.Errorf("ImpactToSeverity(%v) = %v, want %v", tt.impact, result, tt.expected)
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
		tags     map[string]any
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
			tags:     map[string]any{"nist": "AC-2"},
			key:      "cci",
			value:    "CCI-000366",
			expected: false,
		},
		{
			name:     "string match",
			tags:     map[string]any{"cci": "CCI-000366"},
			key:      "cci",
			value:    "CCI-000366",
			expected: true,
		},
		{
			name:     "string case insensitive",
			tags:     map[string]any{"cci": "cci-000366"},
			key:      "cci",
			value:    "CCI-000366",
			expected: true,
		},
		{
			name:     "string no match",
			tags:     map[string]any{"cci": "CCI-000367"},
			key:      "cci",
			value:    "CCI-000366",
			expected: false,
		},
		{
			name:     "array match",
			tags:     map[string]any{"cci": []any{"CCI-000365", "CCI-000366", "CCI-000367"}},
			key:      "cci",
			value:    "CCI-000366",
			expected: true,
		},
		{
			name:     "array no match",
			tags:     map[string]any{"cci": []any{"CCI-000365", "CCI-000367"}},
			key:      "cci",
			value:    "CCI-000366",
			expected: false,
		},
		{
			name:     "string array match",
			tags:     map[string]any{"nist": []string{"AC-2", "CM-6"}},
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
		tags     map[string]any
		key      string
		pattern  string
		expected bool
	}{
		{
			name:     "exact match in array",
			tags:     map[string]any{"nist": []any{"AC-2", "CM-6"}},
			key:      "nist",
			pattern:  "AC-2",
			expected: true,
		},
		{
			name:     "wildcard match in array",
			tags:     map[string]any{"nist": []any{"AC-2", "CM-6"}},
			key:      "nist",
			pattern:  "AC-*",
			expected: true,
		},
		{
			name:     "no match in array",
			tags:     map[string]any{"nist": []any{"AC-2", "CM-6"}},
			key:      "nist",
			pattern:  "AU-*",
			expected: false,
		},
		{
			name:     "string value match",
			tags:     map[string]any{"severity": "high"},
			key:      "severity",
			pattern:  "high",
			expected: true,
		},
		{
			name:     "string value wildcard",
			tags:     map[string]any{"stig_id": "RHEL-07-010010"},
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
		{"critical", "CRIT"},
		{"high", "HIGH"},
		{"medium", "MED "},
		{"low", "LOW "},
		{"informational", "INFO"},
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

// buildQueryFixture creates a synthetic HDF results JSON file in a temp dir.
func buildQueryFixture(t *testing.T, requirements []map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"baselines": []any{
			map[string]any{
				"name":         "Query Test Baseline",
				"checksum":     map[string]any{"algorithm": "sha256", "value": "abc"},
				"requirements": requirements,
			},
		},
		"components": []any{},
		"statistics": map[string]any{},
	})
	if err != nil {
		t.Fatalf("failed to marshal query fixture: %v", err)
	}
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "query-fixture.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write query fixture: %v", err)
	}
	return path
}

// makeRequirement builds a minimal requirement map.
func makeRequirement(id, title string, impact float64) map[string]any {
	return map[string]any{
		"id":           id,
		"title":        title,
		"descriptions": []any{map[string]any{"label": "default", "data": "test"}},
		"impact":       impact,
		"tags":         map[string]any{},
		"results": []any{
			map[string]any{
				"status":    "failed",
				"codeDesc":  "check",
				"startTime": "2025-01-01T00:00:00Z",
			},
		},
	}
}

func TestQueryCommand_TextOutput_ImpactFilter(t *testing.T) {
	// Exercises the human-readable outputQueryResults path (fmt.Printf loop) via
	// a real executeCommand call, covering compareImpact >, >=, < branches in
	// the full CLI pipeline.
	reqs := []map[string]any{
		makeRequirement("REQ-001", "Low impact control", 0.2),
		makeRequirement("REQ-002", "Medium impact control", 0.5),
		makeRequirement("REQ-003", "High impact control", 0.8),
	}
	fixturePath := buildQueryFixture(t, reqs)

	tests := []struct {
		name           string
		impactFilter   string
		wantContain    string
		wantNotContain string
	}{
		{
			name:         "greater than 0.3",
			impactFilter: ">0.3",
			wantContain:  "REQ-002",
		},
		{
			name:         "greater or equal 0.5",
			impactFilter: ">=0.5",
			wantContain:  "REQ-003",
		},
		{
			name:           "less than 0.5",
			impactFilter:   "<0.5",
			wantContain:    "REQ-001",
			wantNotContain: "REQ-003",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := executeCommand("query", "--impact", tt.impactFilter, fixturePath)
			if err != nil {
				t.Fatalf("query command failed: %v (stderr: %s)", err, stderr)
			}
			if tt.wantContain != "" && !strings.Contains(stdout, tt.wantContain) {
				t.Errorf("stdout missing %q, got: %s", tt.wantContain, stdout)
			}
			if tt.wantNotContain != "" && strings.Contains(stdout, tt.wantNotContain) {
				t.Errorf("stdout should not contain %q, got: %s", tt.wantNotContain, stdout)
			}
		})
	}
}

func TestQueryCommand_TextOutput_TitleTruncation(t *testing.T) {
	// A title of 56+ characters exercises the title[:52]+"..." truncation branch
	// in outputQueryResults (line 205–207 of query.go).
	longTitle := fmt.Sprintf("%-56s", "This title is intentionally very long to trigger truncation logic")
	reqs := []map[string]any{
		makeRequirement("REQ-LONG", longTitle, 0.5),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, stderr, err := executeCommand("query", fixturePath)
	if err != nil {
		t.Fatalf("query command failed: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stdout, "...") {
		t.Errorf("expected truncated title with '...', got: %s", stdout)
	}
}
