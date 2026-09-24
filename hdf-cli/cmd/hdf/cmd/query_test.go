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
		// The engine only ever emits a schema severity, so informational is what
		// reaches this label; anything else is an unknown value from a hand-built
		// requirement and shares its bucket.
		{"informational", "INFO"},
		{"unknown", "INFO"},
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

// An impact-0 requirement derives "informational", so that is what selects it.
// The severity vocabulary here has to track DeriveSeverity: when the two drift,
// the value the --severity help advertises matches nothing at all.
func TestQuerySeverity_InformationalSelectsImpactZero(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithStatus("REQ-ZERO", 0.0, "notReviewed"),
		makeReqWithStatus("REQ-MED", 0.5, "failed"),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--severity", "informational", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "1\n", stdout)
}

// The pre-3.7 spelling keeps selecting the same findings, so a saved command
// line does not quietly start matching nothing.
func TestQuerySeverity_LegacyNoneStillSelects(t *testing.T) {
	reqs := []map[string]any{
		makeReqWithStatus("REQ-ZERO", 0.0, "notReviewed"),
		makeReqWithStatus("REQ-MED", 0.5, "failed"),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--severity", "none", "--count", fixturePath)
	require.NoError(t, err)
	assert.Equal(t, "1\n", stdout)
}

// The human-readable label must name the severity the row actually carries.
func TestQuerySeverity_ImpactZeroRendersAsInfo(t *testing.T) {
	fixturePath := buildQueryFixture(t, []map[string]any{makeReqWithStatus("REQ-ZERO", 0.0, "notReviewed")})

	stdout, _, err := executeCommand("query", fixturePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "INFO")
	assert.NotContains(t, stdout, "NONE")
}

// TestQueryCommand_JSONRows_CarryPosition (hdf-libs-js1nv.2, owner-accepted
// additive change): `hdf query --json` marshals engine matches directly, so each
// row carries its position — baselineIndex and index — alongside the six fields
// it always had. Position is the only unique identity a row has: requirement IDs
// repeat within a baseline (grype emits one per package instance), so two rows
// with the same id must still be distinguishable to a CLI consumer.
func TestQueryCommand_JSONRows_CarryPosition(t *testing.T) {
	reqs := []map[string]any{
		makeRequirement("CVE-2024-7264", "curl", 0.5),
		makeRequirement("CVE-2024-7264", "libcurl3-gnutls", 0.5),
		makeRequirement("CVE-2024-0001", "other", 0.9),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, stderr, err := executeCommand("query", "--json", fixturePath)
	require.NoError(t, err, "stderr: %s", stderr)

	var rows []map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &rows))
	require.Len(t, rows, 3)

	// The row shape is exactly the previous six fields plus the two positional ones.
	wantKeys := []string{"id", "title", "status", "impact", "severity", "baseline", "baselineIndex", "index"}
	for i, r := range rows {
		gotKeys := make([]string, 0, len(r))
		for k := range r {
			gotKeys = append(gotKeys, k)
		}
		assert.ElementsMatch(t, wantKeys, gotKeys, "row %d keys", i)
	}

	// Two rows share an id; their positions tell them apart, in document order.
	assert.Equal(t, "CVE-2024-7264", rows[0]["id"])
	assert.Equal(t, "curl", rows[0]["title"])
	assert.Equal(t, float64(0), rows[0]["baselineIndex"])
	assert.Equal(t, float64(0), rows[0]["index"])
	assert.Equal(t, "CVE-2024-7264", rows[1]["id"])
	assert.Equal(t, "libcurl3-gnutls", rows[1]["title"])
	assert.Equal(t, float64(0), rows[1]["baselineIndex"])
	assert.Equal(t, float64(1), rows[1]["index"])
	assert.Equal(t, float64(2), rows[2]["index"])
	assert.Equal(t, "Query Test Baseline", rows[2]["baseline"])
}

// An unrecognized --poams value must be refused before any document is read. A
// value that merely matched nothing would report a clean run over a filter the
// user believed was applied — the false green the threshold epic exists to kill,
// reached through a filter value instead of a spec key.
func TestQueryPoams_UnknownValueIsRejected(t *testing.T) {
	resultsPath := writeTestResults(t)
	for _, bad := range []string{"absent", "present", "expired", "none"} {
		t.Run(bad, func(t *testing.T) {
			_, _, err := executeCommand("query", resultsPath, "--poams", bad)
			require.Error(t, err, "%q must be refused, not silently match nothing", bad)
			assert.Contains(t, err.Error(), "none-valid", "the error must name the legal values")
		})
	}
}

// And the two legal values reach the filter. The fixture carries no POA&M, so
// none-valid selects every requirement and valid selects none — the latter
// failing with the ordinary no-match error rather than the validation one, which
// is what distinguishes "reached the filter and matched nothing" from "refused
// before the document was read".
func TestQueryPoams_LegalValuesReachTheFilter(t *testing.T) {
	resultsPath := writeTestResults(t)

	_, _, err := executeCommand("query", resultsPath, "--poams", "none-valid")
	assert.NoError(t, err, "no requirement in the fixture carries a POA&M, so all of them are none-valid")

	_, _, err = executeCommand("query", resultsPath, "--poams", "valid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching requirements")
	assert.NotContains(t, err.Error(), "unknown --poams value")
}

// A --disposition typo must be refused, not matched against nothing. Override_Type
// is a closed seven-value enum, so "waver" cannot be a legitimate zero-match — and
// a filter that reports a clean run over a predicate that never applied is the
// false green this vocabulary exists to avoid.
func TestQueryDisposition_UnknownValueIsRejected(t *testing.T) {
	resultsPath := writeTestResults(t)
	for _, bad := range []string{"waver", "riskadjustmnet", "suppressed", "none"} {
		t.Run(bad, func(t *testing.T) {
			_, _, err := executeCommand("query", resultsPath, "--disposition", bad)
			require.Error(t, err, "%q must be refused, not silently match nothing", bad)
			assert.Contains(t, err.Error(), "unknown --disposition value")
			assert.Contains(t, err.Error(), "riskAdjustment", "the error must name the legal values")
		})
	}
}

// A legal value reaches the filter; the fixture carries no overrides, so it
// matches nothing and fails with the ordinary no-match error rather than the
// validation one. That is what distinguishes the two outcomes.
func TestQueryDisposition_LegalValueReachesTheFilter(t *testing.T) {
	resultsPath := writeTestResults(t)
	_, _, err := executeCommand("query", resultsPath, "--disposition", "waiver")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching requirements")
	assert.NotContains(t, err.Error(), "unknown --disposition value")
}

// The claim in the CHANGELOG and the README is that an unrecognized --status or
// --severity is refused rather than matched against nothing. This is the test
// that makes the claim true: a filter reporting a clean run over a predicate
// that never applied is the false green this vocabulary exists to prevent.
func TestQueryStatusAndSeverity_UnknownValuesAreRejected(t *testing.T) {
	resultsPath := writeTestResults(t)
	for flag, bad := range map[string]string{"--status": "faild", "--severity": "crit"} {
		t.Run(flag, func(t *testing.T) {
			_, _, err := executeCommand("query", resultsPath, flag, bad)
			require.Error(t, err, "%s %q must be refused, not silently match nothing", flag, bad)
			assert.Contains(t, err.Error(), "unknown "+flag+" value")
		})
	}
}

// And every spelling the engine normalizes reaches the filter through the CLI,
// so a saved command line keeps working and the two surfaces agree.
func TestQueryStatusAndSeverity_AcceptedSpellingsReachTheFilter(t *testing.T) {
	resultsPath := writeTestResults(t)
	for _, spelling := range []string{"not_applicable", "notApplicable", "NOTAPPLICABLE"} {
		_, _, err := executeCommand("query", resultsPath, "--status", spelling)
		// The fixture carries a notApplicable requirement, so every spelling of
		// it must select something rather than erroring or matching nothing.
		assert.NoError(t, err, "%q must select the same requirements as its canonical spelling", spelling)
	}
	// The pre-3.7 severity spelling still names informational on this surface
	// too. Asserted as SELECTION, not as the absence of a validation error: the
	// fixture's impact-0 requirement derives to informational, so if the alias
	// stopped resolving this would exit 1 with "No matching requirements found"
	// and an assertion about the error text would not notice.
	stdout, _, err := executeCommand("query", resultsPath, "--severity", "none")
	require.NoError(t, err, "the pre-3.7 spelling must still select the informational requirement")
	assert.Contains(t, stdout, "SV-004", "and select the same one its canonical spelling does")
}

// --impact validated after the document was read, so a malformed comparison
// reported a parse failure on an unreadable file instead of the filter error,
// and a bulk run repeated the same complaint once per file. Its siblings
// (--status, --severity, --disposition) all validate before any read; this one
// did not. A nonexistent path is what tells the two apart.
func TestQueryImpactFilters_ValidatedBeforeAnyFileIsRead(t *testing.T) {
	for _, flag := range []string{"--impact", "--raw-impact"} {
		t.Run(flag, func(t *testing.T) {
			_, _, err := executeCommand("query", filepath.Join(t.TempDir(), "absent.json"), flag, ">>7")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid "+flag+" filter",
				"the filter must be refused before the file is opened")
		})
	}
}

// The unadjusted twin of --impact. --impact resolves overrides, so without this
// the requirement's own score became unreachable; the pair is what expresses
// "an override may not move a critical below 0.7".
//
// The document has to CARRY an override for this to assert anything: over one
// that does not, the two flags select identically and the test would pass with
// --raw-impact wired to the effective score.
func TestQueryRawImpact_ReachesTheUnadjustedScore(t *testing.T) {
	resultsPath := writeRiskAdjustedResults(t)

	effective, _, err := executeCommand("query", resultsPath, "--impact", ">=0.9")
	require.NoError(t, err)
	assert.NotContains(t, effective, "SV-ADJUSTED",
		"--impact is the post-override score, so the re-scored requirement is out of the band it left")
	assert.Contains(t, effective, "SV-PLAIN")

	raw, _, err := executeCommand("query", resultsPath, "--raw-impact", ">=0.9")
	require.NoError(t, err)
	assert.Contains(t, raw, "SV-ADJUSTED",
		"--raw-impact reaches the requirement's own score, which is what the override moved it from")
	assert.Contains(t, raw, "SV-PLAIN")
	// And it must actually FILTER: without this the test passes on a flag that
	// is parsed and then never reaches the engine, which selects everything.
	assert.NotContains(t, raw, "SV-LOW",
		"--raw-impact must exclude a requirement below the bound, not just include the ones above it")
}

// writeRiskAdjustedResults writes a schema-valid document holding one requirement
// at impact 0.9 governed by a riskAdjustment re-scoring it to 0.3, one at 0.9
// with no override at all, and one below every bound the test uses — the minimum
// needed to tell the effective score from the raw one AND to tell either from a
// filter that never ran.
func writeRiskAdjustedResults(t *testing.T) string {
	t.Helper()
	const doc = `{
  "generator": {"name": "test", "version": "1"},
  "timestamp": "2026-01-01T00:00:00Z",
  "statistics": {"duration": 1.0},
  "baselines": [{"name": "b", "requirements": [
    {"id": "SV-ADJUSTED", "title": "re-scored down", "impact": 0.9, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}],
     "statusOverrides": [{"type": "riskAdjustment", "reason": "environmental context",
       "appliedBy": {"type": "simple", "identifier": "assessor"},
       "appliedAt": "2024-06-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z",
       "impact": {"value": 0.3}}]},
    {"id": "SV-PLAIN", "title": "untouched", "impact": 0.9, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}]},
    {"id": "SV-LOW", "title": "below both bounds", "impact": 0.1, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}]}
  ]}]
}`
	path := filepath.Join(t.TempDir(), "risk-adjusted.json")
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))
	return path
}
