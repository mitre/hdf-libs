package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// NOTE: the filter-helper unit tests (parseImpactFilter, compareImpact,
// tagContains, globToRegex, matchesGlob, tagMatchesGlob) moved with the
// logic into hdf-engine/go/filter_test.go when the query engine was extracted.

func TestSeverityToLabel(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "CRIT"},
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

// ---------------------------------------------------------------------------
// Multi-value (OR) filter tests
// ---------------------------------------------------------------------------

func makeReqWithStatus(id string, impact float64, status string) map[string]any {
	return map[string]any{
		"id":           id,
		"title":        id + " title",
		"descriptions": []any{map[string]any{"label": "default", "data": "test"}},
		"impact":       impact,
		"tags":         map[string]any{},
		"results": []any{
			map[string]any{
				"status":    status,
				"codeDesc":  "check",
				"startTime": "2025-01-01T00:00:00Z",
			},
		},
	}
}

func makeReqWithTags(id string, impact float64, tags map[string]any) map[string]any {
	return map[string]any{
		"id":           id,
		"title":        id + " title",
		"descriptions": []any{map[string]any{"label": "default", "data": "test"}},
		"impact":       impact,
		"tags":         tags,
		"results": []any{
			map[string]any{
				"status":    "failed",
				"codeDesc":  "check",
				"startTime": "2025-01-01T00:00:00Z",
			},
		},
	}
}

func TestQueryMultiStatus_BothMatch(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithStatus("REQ-PASS", 0.5, "passed"),
		makeReqWithStatus("REQ-FAIL", 0.7, "failed"),
		makeReqWithStatus("REQ-ERR", 0.3, "error"),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--status", "failed", "--status", "passed", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "2\n", stdout)
}

func TestQueryMultiStatus_OneMatchesOneDoesNot(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithStatus("REQ-PASS", 0.5, "passed"),
		makeReqWithStatus("REQ-ERR", 0.3, "error"),
	}
	fixturePath := buildQueryFixture(t, reqs)

	// "failed" matches nothing, but "passed" matches REQ-PASS
	stdout, _, err := executeCommand("query", "--status", "failed", "--status", "passed", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "1\n", stdout)
}

func TestQueryMultiSeverity_BothMatch(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithStatus("REQ-HIGH", 0.7, "failed"), // high
		makeReqWithStatus("REQ-MED", 0.5, "failed"),  // medium
		makeReqWithStatus("REQ-CRIT", 0.9, "failed"), // critical
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--severity", "high", "--severity", "critical", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "2\n", stdout)
}

func TestQueryMultiSeverity_OneMatchesOneDoesNot(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithStatus("REQ-MED", 0.5, "failed"), // medium
	}
	fixturePath := buildQueryFixture(t, reqs)

	// "high" matches nothing, "medium" matches REQ-MED
	stdout, _, err := executeCommand("query", "--severity", "high", "--severity", "medium", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "1\n", stdout)
}

func TestQueryMultiCCI_BothMatch(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithTags("REQ-A", 0.7, map[string]any{"cci": []any{"CCI-000366"}}),
		makeReqWithTags("REQ-B", 0.5, map[string]any{"cci": []any{"CCI-000172"}}),
		makeReqWithTags("REQ-C", 0.3, map[string]any{"cci": []any{"CCI-999999"}}),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--cci", "CCI-000366", "--cci", "CCI-000172", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "2\n", stdout)
}

func TestQueryMultiCCI_OneMatchesOneDoesNot(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithTags("REQ-A", 0.7, map[string]any{"cci": []any{"CCI-000366"}}),
	}
	fixturePath := buildQueryFixture(t, reqs)

	// CCI-999999 matches nothing, CCI-000366 matches REQ-A
	stdout, _, err := executeCommand("query", "--cci", "CCI-999999", "--cci", "CCI-000366", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "1\n", stdout)
}

func TestQueryMultiNIST_BothMatch(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithTags("REQ-AC", 0.7, map[string]any{"nist": []any{"AC-2"}}),
		makeReqWithTags("REQ-CM", 0.5, map[string]any{"nist": []any{"CM-6"}}),
		makeReqWithTags("REQ-SI", 0.3, map[string]any{"nist": []any{"SI-2"}}),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--nist", "AC-2", "--nist", "CM-6", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "2\n", stdout)
}

func TestQueryMultiNIST_GlobOneMatchesOneDoesNot(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithTags("REQ-AC", 0.7, map[string]any{"nist": []any{"AC-2"}}),
		makeReqWithTags("REQ-CM", 0.5, map[string]any{"nist": []any{"CM-6"}}),
	}
	fixturePath := buildQueryFixture(t, reqs)

	// "IA-*" matches nothing, "AC-*" matches REQ-AC
	stdout, _, err := executeCommand("query", "--nist", "IA-*", "--nist", "AC-*", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "1\n", stdout)
}

func TestQueryMultiTag_BothMatch(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithTags("REQ-HIGH", 0.7, map[string]any{"severity": "high"}),
		makeReqWithTags("REQ-CRIT", 0.9, map[string]any{"severity": "critical"}),
		makeReqWithTags("REQ-MED", 0.5, map[string]any{"severity": "medium"}),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--tag", "severity:high", "--tag", "severity:critical", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "2\n", stdout)
}

func TestQueryMultiTag_OneMatchesOneDoesNot(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithTags("REQ-MED", 0.5, map[string]any{"severity": "medium"}),
	}
	fixturePath := buildQueryFixture(t, reqs)

	// severity:high matches nothing, severity:medium matches REQ-MED
	stdout, _, err := executeCommand("query", "--tag", "severity:high", "--tag", "severity:medium", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "1\n", stdout)
}

func TestQueryMultiFlag_ANDAcrossORWithin(t *testing.T) {
	// Combines multi-status (OR) with severity (AND)
	reqs := []map[string]any{
		makeReqWithStatus("REQ-FAIL-HIGH", 0.7, "failed"), // failed + high
		makeReqWithStatus("REQ-PASS-HIGH", 0.7, "passed"), // passed + high
		makeReqWithStatus("REQ-FAIL-MED", 0.5, "failed"),  // failed + medium
		makeReqWithStatus("REQ-ERR-HIGH", 0.7, "error"),   // error + high
	}
	fixturePath := buildQueryFixture(t, reqs)

	// (failed OR passed) AND high => REQ-FAIL-HIGH + REQ-PASS-HIGH
	stdout, _, err := executeCommand("query",
		"--status", "failed", "--status", "passed",
		"--severity", "high",
		"--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "2\n", stdout)
}
