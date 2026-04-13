package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitre/hdf-cli/pkg/diff/exitcodes"
	diffTypes "github.com/mitre/hdf-cli/pkg/diff/types"
)

// --- Fixture builders for diff tests ---

// syntheticHDFBefore builds a fixture representing a "before" scan with:
//   - REQ-001: failed
//   - REQ-002: passed
//   - REQ-003: passed
//   - REQ-004: failed
func syntheticHDFBefore() map[string]interface{} {
	return map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "Diff Test Baseline",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "abc123"},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "failed"),
					makeRequirementWithResultStatus("REQ-002", "passed"),
					makeRequirementWithResultStatus("REQ-003", "passed"),
					makeRequirementWithResultStatus("REQ-004", "failed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
}

// syntheticHDFAfter builds a fixture representing an "after" scan with:
//   - REQ-001: passed  (was failed → fixed)
//   - REQ-002: failed  (was passed → regressed)
//   - REQ-003: passed  (was passed → unchanged)
//   - REQ-005: passed  (new - not in before)
//
// REQ-004 is absent (was in before but not in after).
func syntheticHDFAfter() map[string]interface{} {
	return map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "Diff Test Baseline",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "def456"},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "passed"),
					makeRequirementWithResultStatus("REQ-002", "failed"),
					makeRequirementWithResultStatus("REQ-003", "passed"),
					makeRequirementWithResultStatus("REQ-005", "passed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
}

// syntheticHDFUpdated builds a fixture where REQ-001 changes from failed to notReviewed
// (neither passing nor failing → "updated").
func syntheticHDFUpdated() map[string]interface{} {
	return map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "Diff Test Baseline",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "ghi789"},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "notReviewed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
}

// syntheticHDFSingleFailed builds a fixture with one failed requirement.
func syntheticHDFSingleFailed() map[string]interface{} {
	return map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "Diff Test Baseline",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "jkl012"},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "failed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
}

// syntheticHDFNoRegressions builds a fixture where REQ-001 goes from failed → passed (fixed, no regressions).
func syntheticHDFSinglePassed() map[string]interface{} {
	return map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "Diff Test Baseline",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "mno345"},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "passed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
}

// TestDiffCommand_BasicComparison verifies that the diff command correctly
// classifies requirements as fixed, regressed, unchanged, new, and absent.
func TestDiffCommand_BasicComparison(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should contain summary with correct counts
	if !strings.Contains(stdout, "1 fixed") {
		t.Errorf("expected '1 fixed' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 regressed") {
		t.Errorf("expected '1 regressed' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 unchanged") {
		t.Errorf("expected '1 unchanged' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 new") {
		t.Errorf("expected '1 new' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 absent") {
		t.Errorf("expected '1 absent' in output, got:\n%s", stdout)
	}
}

// TestDiffCommand_IdenticalFiles verifies that diffing a file against itself
// produces all "unchanged" results.
func TestDiffCommand_IdenticalFiles(t *testing.T) {
	path := writeHDFFixture(t, syntheticHDFBefore())

	stdout, stderr, err := executeCommand("diff", path, path)
	allowExitCode(t, err, stderr)

	// All 4 requirements should be unchanged
	if !strings.Contains(stdout, "4 unchanged") {
		t.Errorf("expected '4 unchanged' in output, got:\n%s", stdout)
	}

	// Should have no fixed, regressed, new, or absent
	if strings.Contains(stdout, "fixed") && !strings.Contains(stdout, "0 fixed") {
		t.Errorf("expected 0 fixed in output, got:\n%s", stdout)
	}
}

// TestDiffCommand_HidesUnchangedByDefault verifies unchanged requirements are
// not shown in table output unless --all is passed.
func TestDiffCommand_HidesUnchangedByDefault(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// REQ-003 is unchanged (passed→passed) — should NOT appear in table output
	if strings.Contains(stdout, "REQ-003") {
		t.Errorf("unchanged REQ-003 should be hidden by default, got:\n%s", stdout)
	}

	// But changed requirements should appear
	if !strings.Contains(stdout, "REQ-001") {
		t.Errorf("expected REQ-001 (fixed) in output, got:\n%s", stdout)
	}

	// Summary should still show unchanged count
	if !strings.Contains(stdout, "1 unchanged") {
		t.Errorf("summary should include unchanged count, got:\n%s", stdout)
	}
}

// TestDiffCommand_AllFlag verifies --all includes unchanged requirements.
func TestDiffCommand_AllFlag(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--all", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// REQ-003 is unchanged — should appear with --all
	if !strings.Contains(stdout, "REQ-003") {
		t.Errorf("expected REQ-003 in --all output, got:\n%s", stdout)
	}
}

// TestDiffCommand_JSONOutput verifies that --json produces valid JSON with the correct structure.
func TestDiffCommand_JSONOutput(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--json", oldPath, newPath)
	allowExitCode(t, err, stderr)

	var output map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("diff --json output is not valid JSON: %v\noutput: %s", err, stdout)
	}

	// Check required top-level fields
	if _, ok := output["formatVersion"]; !ok {
		t.Error("expected 'formatVersion' key in JSON output")
	}
	if _, ok := output["comparisonMode"]; !ok {
		t.Error("expected 'comparisonMode' key in JSON output")
	}
	if _, ok := output["summary"]; !ok {
		t.Error("expected 'summary' key in JSON output")
	}
	if _, ok := output["requirementDiffs"]; !ok {
		t.Error("expected 'requirementDiffs' key in JSON output")
	}

	// Check summary counts
	summary, ok := output["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'summary' to be a map")
	}

	for _, key := range []string{"total", "fixed", "regressed", "new", "absent", "unchanged", "updated"} {
		if _, exists := summary[key]; !exists {
			t.Errorf("expected key %q in summary", key)
		}
	}

	// Verify total = 5 (REQ-001 through REQ-005)
	if total, ok := summary["total"].(float64); ok {
		if int(total) != 5 {
			t.Errorf("expected total=5, got %v", total)
		}
	}

	// Check requirements array
	reqs, ok := output["requirementDiffs"].([]interface{})
	if !ok {
		t.Fatal("expected 'requirementDiffs' to be an array")
	}
	if len(reqs) == 0 {
		t.Error("expected non-empty requirements array")
	}

	// Verify first requirement has expected fields
	firstReq, ok := reqs[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected requirement to be a map")
	}
	for _, key := range []string{"id", "state"} {
		if _, exists := firstReq[key]; !exists {
			t.Errorf("expected key %q in requirement", key)
		}
	}
}

// TestDiffCommand_FilterFixed verifies that --fixed only shows fixed requirements.
func TestDiffCommand_FilterFixed(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--fixed", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should show REQ-001 (fixed)
	if !strings.Contains(stdout, "REQ-001") {
		t.Errorf("expected REQ-001 in --fixed output, got:\n%s", stdout)
	}

	// Should NOT show regressed, new, absent, or unchanged requirements
	if strings.Contains(stdout, "REQ-002") {
		t.Errorf("--fixed should not show REQ-002 (regressed), got:\n%s", stdout)
	}
	if strings.Contains(stdout, "REQ-005") {
		t.Errorf("--fixed should not show REQ-005 (new), got:\n%s", stdout)
	}
}

// TestDiffCommand_FilterRegressed verifies that --regressed only shows regressions.
func TestDiffCommand_FilterRegressed(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--regressed", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should show REQ-002 (regressed)
	if !strings.Contains(stdout, "REQ-002") {
		t.Errorf("expected REQ-002 in --regressed output, got:\n%s", stdout)
	}

	// Should NOT show fixed
	if strings.Contains(stdout, "REQ-001") {
		t.Errorf("--regressed should not show REQ-001 (fixed), got:\n%s", stdout)
	}
}

// allowExitCode tolerates exitCodeError (expected for diff returning 1 on differences).
func allowExitCode(t *testing.T, err error, stderr string) {
	t.Helper()
	if err == nil {
		return
	}
	var exitErr *exitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected error: %v (stderr: %s)", err, stderr)
	}
}

// requireExitCode is a test helper that asserts the error is an *exitCodeError
// with the expected exit code.
func requireExitCode(t *testing.T, err error, wantCode int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected non-nil error with exit code %d, got nil", wantCode)
	}
	var exitErr *exitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exitCodeError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != wantCode {
		t.Errorf("expected exit code %d, got %d", wantCode, exitErr.ExitCode())
	}
}

// TestDiffCommand_DefaultExitCode_Differences verifies exit code 1 by default
// when differences exist (GNU diff convention).
func TestDiffCommand_DefaultExitCode_Differences(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	_, _, err := executeCommand("diff", oldPath, newPath)
	requireExitCode(t, err, exitcodes.Differences)
}

// TestDiffCommand_DefaultExitCode_Identical verifies exit code 0 by default
// when files are identical.
func TestDiffCommand_DefaultExitCode_Identical(t *testing.T) {
	path := writeHDFFixture(t, syntheticHDFBefore())

	_, _, err := executeCommand("diff", path, path)
	if err != nil {
		t.Errorf("expected exit 0 for identical files, got: %v", err)
	}
}

// TestDiffCommand_ExitCode_Differences verifies --exit-code flag (now a no-op,
// basic exit codes are always on).
func TestDiffCommand_ExitCode_Differences(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	_, _, err := executeCommand("diff", "--exit-code", oldPath, newPath)
	requireExitCode(t, err, exitcodes.Differences)
}

// TestDiffCommand_ExitCode_Identical verifies that --exit-code returns exit code 0
// when files are identical.
func TestDiffCommand_ExitCode_Identical(t *testing.T) {
	path := writeHDFFixture(t, syntheticHDFBefore())

	_, stderr, err := executeCommand("diff", "--exit-code", path, path)
	if err != nil {
		t.Errorf("expected no error (exit code 0) for identical files, got: %v (stderr: %s)", err, stderr)
	}
}

// TestDiffCommand_ExitCode_FixesOnly verifies that --exit-code returns exit code 1
// even when only fixes are present (any difference = exit 1).
func TestDiffCommand_ExitCode_FixesOnly(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFSingleFailed())
	newPath := writeHDFFixture(t, syntheticHDFSinglePassed())

	_, _, err := executeCommand("diff", "--exit-code", oldPath, newPath)
	requireExitCode(t, err, exitcodes.Differences)
}

// --- Detailed exit code tests ---

// TestDiffCommand_DetailedExitCode_Identical verifies identical files → exit 0.
func TestDiffCommand_DetailedExitCode_Identical(t *testing.T) {
	path := writeHDFFixture(t, syntheticHDFBefore())

	_, stderr, err := executeCommand("diff", "--detailed-exitcode", path, path)
	if err != nil {
		t.Errorf("expected no error (exit code 0) for identical files, got: %v (stderr: %s)", err, stderr)
	}
}

// TestDiffCommand_DetailedExitCode_FixesOnly verifies fixes-only → exit 10.
func TestDiffCommand_DetailedExitCode_FixesOnly(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFSingleFailed())
	newPath := writeHDFFixture(t, syntheticHDFSinglePassed())

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitcodes.FixesOnly)
}

// TestDiffCommand_DetailedExitCode_RegressionsOnly verifies regressions-only → exit 11.
func TestDiffCommand_DetailedExitCode_RegressionsOnly(t *testing.T) {
	// passed → failed = regression
	oldPath := writeHDFFixture(t, syntheticHDFSinglePassed())
	newPath := writeHDFFixture(t, syntheticHDFSingleFailed())

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitcodes.RegressionsOnly)
}

// TestDiffCommand_DetailedExitCode_Mixed verifies mixed fixes+regressions → exit 12.
func TestDiffCommand_DetailedExitCode_Mixed(t *testing.T) {
	// syntheticHDFBefore → syntheticHDFAfter has both fixes and regressions:
	// REQ-001: failed→passed (fixed), REQ-002: passed→failed (regressed)
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitcodes.Mixed)
}

// TestDiffCommand_DetailedExitCode_BaselineChanged verifies new/absent controls only → exit 13.
func TestDiffCommand_DetailedExitCode_BaselineChanged(t *testing.T) {
	// Old has REQ-001, new has REQ-002 — both passed, so no fix/regression.
	// REQ-001 becomes absent, REQ-002 becomes new → baseline changed.
	oldFixture := map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "Baseline Changed Test",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "aaa"},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", "passed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
	newFixture := map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "Baseline Changed Test",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": "bbb"},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-002", "passed"),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}

	oldPath := writeHDFFixture(t, oldFixture)
	newPath := writeHDFFixture(t, newFixture)

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitcodes.BaselineChanged)
}

// TestDiffCommand_DetailedExitCode_DriftOnly verifies metadata-only changes → exit 14.
func TestDiffCommand_DetailedExitCode_DriftOnly(t *testing.T) {
	// REQ-001 failed→notReviewed is classified as "updated" (not fixed or regressed).
	// No new/absent controls → drift only.
	oldPath := writeHDFFixture(t, syntheticHDFSingleFailed())
	newPath := writeHDFFixture(t, syntheticHDFUpdated())

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitcodes.DriftOnly)
}

// TestDiffCommand_DetailedExitCode_HelpText verifies the flag appears in help.
func TestDiffCommand_DetailedExitCode_HelpText(t *testing.T) {
	stdout, _, _ := executeCommand("diff", "--help")

	if !strings.Contains(stdout, "detailed-exitcode") {
		t.Errorf("expected 'detailed-exitcode' in help output, got:\n%s", stdout)
	}
}

// TestDiffCommand_MissingFile verifies error handling for non-existent files.
func TestDiffCommand_MissingFile(t *testing.T) {
	validPath := writeHDFFixture(t, syntheticHDFBefore())

	_, _, err := executeCommand("diff", "nonexistent.json", validPath)
	if err == nil {
		t.Error("expected error for missing old file")
	}

	_, _, err = executeCommand("diff", validPath, "nonexistent.json")
	if err == nil {
		t.Error("expected error for missing new file")
	}
}

// TestDiffCommand_TooFewArgs verifies error when less than 2 arguments provided.
func TestDiffCommand_TooFewArgs(t *testing.T) {
	_, _, err := executeCommand("diff")
	if err == nil {
		t.Error("expected error with no arguments")
	}

	validPath := writeHDFFixture(t, syntheticHDFBefore())
	_, _, err = executeCommand("diff", validPath)
	if err == nil {
		t.Error("expected error with only one argument")
	}
}

// TestDiffCommand_MarkdownOutput verifies that --format markdown produces markdown table output.
func TestDiffCommand_MarkdownOutput(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--format", "markdown", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Markdown tables have | delimiters and --- header separators
	if !strings.Contains(stdout, "|") {
		t.Errorf("expected markdown table with '|' delimiters, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "---") {
		t.Errorf("expected markdown table header separator '---', got:\n%s", stdout)
	}
}

// TestDiffCommand_UpdatedState verifies the "updated" classification
// (status changed but neither fixed nor regressed, e.g., failed → notReviewed).
func TestDiffCommand_UpdatedState(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFSingleFailed())
	newPath := writeHDFFixture(t, syntheticHDFUpdated())

	stdout, stderr, err := executeCommand("diff", "--json", oldPath, newPath)
	allowExitCode(t, err, stderr)

	var output map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	summary := output["summary"].(map[string]interface{})
	if updated, ok := summary["updated"].(float64); !ok || int(updated) != 1 {
		t.Errorf("expected 1 updated, got %v", summary["updated"])
	}
}

// TestDiffCommand_FilterNew verifies that --new only shows new requirements.
func TestDiffCommand_FilterNew(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--new", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should show REQ-005 (new)
	if !strings.Contains(stdout, "REQ-005") {
		t.Errorf("expected REQ-005 in --new output, got:\n%s", stdout)
	}

	// Should NOT show fixed or regressed
	if strings.Contains(stdout, "REQ-001") {
		t.Errorf("--new should not show REQ-001 (fixed), got:\n%s", stdout)
	}
}

// TestDiffCommand_FilterAbsent verifies that --absent only shows absent requirements.
func TestDiffCommand_FilterAbsent(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--absent", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should show REQ-004 (absent)
	if !strings.Contains(stdout, "REQ-004") {
		t.Errorf("expected REQ-004 in --absent output, got:\n%s", stdout)
	}

	// Should NOT show fixed or regressed
	if strings.Contains(stdout, "REQ-001") {
		t.Errorf("--absent should not show REQ-001 (fixed), got:\n%s", stdout)
	}
}

// --- Unit tests for exit code computation functions ---

// TestComputeBasicExitCode verifies the GNU diff compatible exit code logic.
func TestComputeBasicExitCode(t *testing.T) {
	tests := []struct {
		name    string
		summary diffTypes.ComparisonSummary
		want    int
	}{
		{"identical", diffTypes.ComparisonSummary{Total: 10, Unchanged: 10}, exitcodes.Identical},
		{"empty", diffTypes.ComparisonSummary{Total: 0, Unchanged: 0}, exitcodes.Identical},
		{"fixes", diffTypes.ComparisonSummary{Total: 10, Fixed: 3, Unchanged: 7}, exitcodes.Differences},
		{"regressions", diffTypes.ComparisonSummary{Total: 10, Regressed: 2, Unchanged: 8}, exitcodes.Differences},
		{"mixed", diffTypes.ComparisonSummary{Total: 10, Fixed: 1, Regressed: 1, Unchanged: 8}, exitcodes.Differences},
		{"new only", diffTypes.ComparisonSummary{Total: 12, New: 2, Unchanged: 10}, exitcodes.Differences},
		{"absent only", diffTypes.ComparisonSummary{Total: 10, Absent: 3, Unchanged: 7}, exitcodes.Differences},
		{"updated only", diffTypes.ComparisonSummary{Total: 10, Updated: 1, Unchanged: 9}, exitcodes.Differences},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitcodes.ComputeBasicExitCode(tt.summary)
			if got != tt.want {
				t.Errorf("exitcodes.ComputeBasicExitCode(%v) = %d, want %d", tt.summary, got, tt.want)
			}
		})
	}
}

// TestComputeDetailedExitCode verifies the detailed exit code classification.
func TestComputeDetailedExitCode(t *testing.T) {
	tests := []struct {
		name    string
		summary diffTypes.ComparisonSummary
		want    int
	}{
		{"identical", diffTypes.ComparisonSummary{Total: 10, Unchanged: 10}, exitcodes.Identical},
		{"empty", diffTypes.ComparisonSummary{Total: 0, Unchanged: 0}, exitcodes.Identical},
		{"fixes only", diffTypes.ComparisonSummary{Total: 10, Fixed: 3, Unchanged: 7}, exitcodes.FixesOnly},
		{"regressions only", diffTypes.ComparisonSummary{Total: 10, Regressed: 2, Unchanged: 8}, exitcodes.RegressionsOnly},
		{"mixed", diffTypes.ComparisonSummary{Total: 10, Fixed: 2, Regressed: 1, Unchanged: 7}, exitcodes.Mixed},
		{"new only", diffTypes.ComparisonSummary{Total: 12, New: 2, Unchanged: 10}, exitcodes.BaselineChanged},
		{"absent only", diffTypes.ComparisonSummary{Total: 10, Absent: 3, Unchanged: 7}, exitcodes.BaselineChanged},
		{"new and absent", diffTypes.ComparisonSummary{Total: 10, New: 1, Absent: 1, Unchanged: 8}, exitcodes.BaselineChanged},
		{"updated only (drift)", diffTypes.ComparisonSummary{Total: 10, Updated: 1, Unchanged: 9}, exitcodes.DriftOnly},
		{"fixes + new (fixes take priority)", diffTypes.ComparisonSummary{Total: 10, Fixed: 2, New: 1, Unchanged: 7}, exitcodes.FixesOnly},
		{"regressions + absent (regressions take priority)", diffTypes.ComparisonSummary{Total: 10, Regressed: 1, Absent: 2, Unchanged: 7}, exitcodes.RegressionsOnly},
		{"all categories present", diffTypes.ComparisonSummary{Total: 10, Fixed: 1, Regressed: 1, New: 1, Absent: 1, Unchanged: 6}, exitcodes.Mixed},
		{"updated + new (baseline takes priority over drift)", diffTypes.ComparisonSummary{Total: 10, Updated: 1, New: 1, Unchanged: 8}, exitcodes.BaselineChanged},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitcodes.ComputeDetailedExitCode(tt.summary)
			if got != tt.want {
				t.Errorf("exitcodes.ComputeDetailedExitCode(%v) = %d, want %d", tt.summary, got, tt.want)
			}
		})
	}
}

// TestDiffCommand_HelpOutput verifies the help text is available.
func TestDiffCommand_HelpOutput(t *testing.T) {
	stdout, _, _ := executeCommand("diff", "--help")

	if !strings.Contains(stdout, "diff") {
		t.Errorf("expected 'diff' in help output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "old-file") {
		t.Errorf("expected 'old-file' in help output, got:\n%s", stdout)
	}
}

// --- System-aware diff tests ---

// makeTwoBaselineFixture builds an HDF fixture with two baselines (RHEL9-STIG, PostgreSQL-STIG).
// Parameters control the checksum and per-requirement statuses.
func makeTwoBaselineFixture(
	checksum1, checksum2 string,
	req1Status, req2Status, req3Status, req4Status string,
) map[string]interface{} {
	return map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{
				"name":     "RHEL9-STIG",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": checksum1},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-001", req1Status),
					makeRequirementWithResultStatus("REQ-002", req2Status),
				},
			},
			map[string]interface{}{
				"name":     "PostgreSQL-STIG",
				"checksum": map[string]interface{}{"algorithm": "sha256", "value": checksum2},
				"requirements": []interface{}{
					makeRequirementWithResultStatus("REQ-003", req3Status),
					makeRequirementWithResultStatus("REQ-004", req4Status),
				},
			},
		},
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
}

// syntheticHDFTwoBaselinesOld builds a fixture with two baselines for system-aware testing.
// RHEL9-STIG: REQ-001 (failed), REQ-002 (passed). PostgreSQL-STIG: REQ-003 (passed), REQ-004 (failed).
func syntheticHDFTwoBaselinesOld() map[string]interface{} {
	return makeTwoBaselineFixture("aaa111", "bbb222", "failed", "passed", "passed", "failed")
}

// syntheticHDFTwoBaselinesNew builds a "new" fixture with the same two baselines.
// RHEL9-STIG: REQ-001 now passed (fixed), REQ-002 still passed (unchanged).
// PostgreSQL-STIG: REQ-003 still passed (unchanged), REQ-004 still failed (unchanged).
func syntheticHDFTwoBaselinesNew() map[string]interface{} {
	return makeTwoBaselineFixture("ccc333", "ddd444", "passed", "passed", "passed", "failed")
}

// syntheticSystemDoc builds a minimal system document with two components.
func syntheticSystemDoc() map[string]interface{} {
	return map[string]interface{}{
		"name": "TestSystem",
		"components": []interface{}{
			map[string]interface{}{
				"name":         "WebTier",
				"type":         "software",
				"baselineRefs": []interface{}{"RHEL9-STIG"},
			},
			map[string]interface{}{
				"name":         "DatabaseTier",
				"type":         "software",
				"baselineRefs": []interface{}{"PostgreSQL-STIG"},
			},
		},
	}
}

// writeJSONFixture writes arbitrary JSON data to a temp file and returns the path.
func writeJSONFixture(t *testing.T, data interface{}) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "fixture.json")
	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, jsonData, 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	return path
}

// TestDiffCommand_SystemFlag verifies that --system produces component-grouped output.
func TestDiffCommand_SystemFlag(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFTwoBaselinesOld())
	newPath := writeHDFFixture(t, syntheticHDFTwoBaselinesNew())
	sysPath := writeJSONFixture(t, syntheticSystemDoc())

	stdout, stderr, err := executeCommand("diff", "--system", sysPath, oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should contain component names
	if !strings.Contains(stdout, "WebTier") {
		t.Errorf("expected 'WebTier' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "DatabaseTier") {
		t.Errorf("expected 'DatabaseTier' in output, got:\n%s", stdout)
	}

	// Should contain compliance info
	if !strings.Contains(stdout, "Old Compliance") {
		t.Errorf("expected 'Old Compliance' header in output, got:\n%s", stdout)
	}
}

// TestDiffCommand_SystemFlag_JSON verifies that --system with --json includes componentSummaries.
func TestDiffCommand_SystemFlag_JSON(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFTwoBaselinesOld())
	newPath := writeHDFFixture(t, syntheticHDFTwoBaselinesNew())
	sysPath := writeJSONFixture(t, syntheticSystemDoc())

	stdout, stderr, err := executeCommand("diff", "--json", "--system", sysPath, oldPath, newPath)
	allowExitCode(t, err, stderr)

	var output map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, stdout)
	}

	// Should have componentSummaries
	cs, ok := output["componentDiffs"].([]interface{})
	if !ok {
		t.Fatalf("expected 'componentDiffs' array in JSON output, got: %v", output["componentDiffs"])
	}
	if len(cs) != 2 {
		t.Errorf("expected 2 component summaries, got %d", len(cs))
	}

	// Verify first component has expected fields
	first, ok := cs[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected component summary to be a map")
	}
	for _, key := range []string{"name", "baselineRefs", "summary", "oldCompliance", "newCompliance", "complianceDelta"} {
		if _, exists := first[key]; !exists {
			t.Errorf("expected key %q in component summary", key)
		}
	}
}

// TestDiffCommand_SystemFlag_MissingFile verifies error when system file doesn't exist.
func TestDiffCommand_SystemFlag_MissingFile(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFTwoBaselinesOld())
	newPath := writeHDFFixture(t, syntheticHDFTwoBaselinesNew())

	_, _, err := executeCommand("diff", "--system", "nonexistent-system.json", oldPath, newPath)
	if err == nil {
		t.Error("expected error for missing system file")
	}
}

// TestDiffCommand_GroupByBaseline verifies --group-by baseline adds a Baseline column.
func TestDiffCommand_GroupByBaseline(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFTwoBaselinesOld())
	newPath := writeHDFFixture(t, syntheticHDFTwoBaselinesNew())

	// Without --all, only changed requirements are shown
	stdout, stderr, err := executeCommand("diff", "--group-by", "baseline", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should have a Baseline column header
	if !strings.Contains(stdout, "Baseline") {
		t.Errorf("expected 'Baseline' column header, got:\n%s", stdout)
	}
	// Changed requirement should show its baseline
	if !strings.Contains(stdout, "RHEL9-STIG") {
		t.Errorf("expected 'RHEL9-STIG' in grouped output, got:\n%s", stdout)
	}

	// With --all, unchanged requirements (including PostgreSQL-STIG) are shown
	stdout, stderr, err = executeCommand("diff", "--group-by", "baseline", "--all", oldPath, newPath)
	allowExitCode(t, err, stderr)

	if !strings.Contains(stdout, "PostgreSQL-STIG") {
		t.Errorf("expected 'PostgreSQL-STIG' in --all grouped output, got:\n%s", stdout)
	}
}

// TestDiffCommand_SystemAndGroupByMutuallyExclusive verifies that --system and --group-by
// cannot be used together.
func TestDiffCommand_SystemAndGroupByMutuallyExclusive(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFTwoBaselinesOld())
	newPath := writeHDFFixture(t, syntheticHDFTwoBaselinesNew())
	sysPath := writeJSONFixture(t, syntheticSystemDoc())

	_, _, err := executeCommand("diff", "--system", sysPath, "--group-by", "baseline", oldPath, newPath)
	if err == nil {
		t.Error("expected error when both --system and --group-by are provided")
	}
}

// TestDiffCommand_SystemFlag_ComplianceValues verifies compliance percentages are correct.
func TestDiffCommand_SystemFlag_ComplianceValues(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFTwoBaselinesOld())
	newPath := writeHDFFixture(t, syntheticHDFTwoBaselinesNew())
	sysPath := writeJSONFixture(t, syntheticSystemDoc())

	stdout, stderr, err := executeCommand("diff", "--json", "--system", sysPath, oldPath, newPath)
	allowExitCode(t, err, stderr)

	var output struct {
		ComponentSummaries []struct {
			Name            string  `json:"name"`
			OldCompliance   float64 `json:"oldCompliance"`
			NewCompliance   float64 `json:"newCompliance"`
			ComplianceDelta float64 `json:"complianceDelta"`
		} `json:"componentSummaries"`
	}
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// WebTier (RHEL9-STIG): old = 1/2 passed = 50%, new = 2/2 passed = 100%
	for _, cs := range output.ComponentSummaries {
		switch cs.Name {
		case "WebTier":
			if cs.OldCompliance != 50 {
				t.Errorf("WebTier old compliance: got %.0f%%, want 50%%", cs.OldCompliance)
			}
			if cs.NewCompliance != 100 {
				t.Errorf("WebTier new compliance: got %.0f%%, want 100%%", cs.NewCompliance)
			}
			if cs.ComplianceDelta != 50 {
				t.Errorf("WebTier compliance delta: got %.0f%%, want 50%%", cs.ComplianceDelta)
			}
		case "DatabaseTier":
			// PostgreSQL-STIG: old = 1/2 passed = 50%, new = 1/2 passed = 50%
			if cs.OldCompliance != 50 {
				t.Errorf("DatabaseTier old compliance: got %.0f%%, want 50%%", cs.OldCompliance)
			}
			if cs.NewCompliance != 50 {
				t.Errorf("DatabaseTier new compliance: got %.0f%%, want 50%%", cs.NewCompliance)
			}
			if cs.ComplianceDelta != 0 {
				t.Errorf("DatabaseTier compliance delta: got %.0f%%, want 0%%", cs.ComplianceDelta)
			}
		}
	}
}

// TestDiffCommand_HelpOutput_SystemFlag verifies --system appears in help.
func TestDiffCommand_HelpOutput_SystemFlag(t *testing.T) {
	stdout, _, _ := executeCommand("diff", "--help")

	if !strings.Contains(stdout, "--system") {
		t.Errorf("expected '--system' in help output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "--group-by") {
		t.Errorf("expected '--group-by' in help output, got:\n%s", stdout)
	}
}

// --- System document diff tests (systemDrift mode) ---

// UUIDs for system diff test fixtures.
const (
	testUUIDWebTier  = "aaaaaaaa-1111-4000-a000-000000000001"
	testUUIDDatabase = "bbbbbbbb-2222-4000-a000-000000000002"
	testUUIDCache    = "cccccccc-3333-4000-a000-000000000003"
	testUUIDSameID   = "dddddddd-4444-4000-a000-000000000004"
)

// syntheticSystemOld builds a system document with two components and one data flow.
func syntheticSystemOld() map[string]interface{} {
	return map[string]interface{}{
		"name": "Portal-Prod",
		"components": []interface{}{
			map[string]interface{}{
				"name":        "WebTier",
				"type":        "application",
				"componentId": testUUIDWebTier,
				"description": "Frontend web server",
			},
			map[string]interface{}{
				"name":        "Database",
				"type":        "database",
				"componentId": testUUIDDatabase,
				"description": "PostgreSQL primary",
			},
		},
		"dataFlows": []interface{}{
			map[string]interface{}{
				"from":     testUUIDWebTier,
				"to":       testUUIDDatabase,
				"protocol": "JDBC",
				"port":     5432,
			},
		},
	}
}

// syntheticSystemNew builds a modified system document:
//   - WebTier: description changed (updated)
//   - Database: removed (absent)
//   - CacheLayer: added (new)
//   - Data flow changed: port updated, new flow added
func syntheticSystemNew() map[string]interface{} {
	return map[string]interface{}{
		"name": "Portal-Prod",
		"components": []interface{}{
			map[string]interface{}{
				"name":        "WebTier",
				"type":        "application",
				"componentId": testUUIDWebTier,
				"description": "Frontend web server (updated)",
			},
			map[string]interface{}{
				"name":        "CacheLayer",
				"type":        "application",
				"componentId": testUUIDCache,
				"description": "Redis cache tier",
			},
		},
		"dataFlows": []interface{}{
			map[string]interface{}{
				"from":     testUUIDWebTier,
				"to":       testUUIDDatabase,
				"protocol": "JDBC",
				"port":     5433,
			},
			map[string]interface{}{
				"from":     testUUIDWebTier,
				"to":       testUUIDCache,
				"protocol": "TCP",
				"port":     6379,
			},
		},
	}
}

// TestDiffCommand_SystemDrift_BasicComparison verifies that diffing two system
// documents auto-detects systemDrift mode and classifies components.
func TestDiffCommand_SystemDrift_BasicComparison(t *testing.T) {
	oldPath := writeJSONFixture(t, syntheticSystemOld())
	newPath := writeJSONFixture(t, syntheticSystemNew())

	stdout, stderr, err := executeCommand("diff", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should contain component names
	if !strings.Contains(stdout, "WebTier") {
		t.Errorf("expected 'WebTier' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Database") {
		t.Errorf("expected 'Database' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "CacheLayer") {
		t.Errorf("expected 'CacheLayer' in output, got:\n%s", stdout)
	}

	// Should indicate systemDrift mode
	if !strings.Contains(stdout, "System") {
		t.Errorf("expected system-related label in output, got:\n%s", stdout)
	}
}

// TestDiffCommand_SystemDrift_JSON verifies JSON output for system document diffs.
func TestDiffCommand_SystemDrift_JSON(t *testing.T) {
	oldPath := writeJSONFixture(t, syntheticSystemOld())
	newPath := writeJSONFixture(t, syntheticSystemNew())

	stdout, stderr, err := executeCommand("diff", "--json", oldPath, newPath)
	allowExitCode(t, err, stderr)

	var output map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(stdout), &output); jsonErr != nil {
		t.Fatalf("diff --json output is not valid JSON: %v\noutput: %s", jsonErr, stdout)
	}

	// Check comparison mode
	if mode, ok := output["comparisonMode"].(string); !ok || mode != "systemDrift" {
		t.Errorf("expected comparisonMode='systemDrift', got %v", output["comparisonMode"])
	}

	// Check component diffs
	diffs, ok := output["componentDiffs"].([]interface{})
	if !ok {
		t.Fatalf("expected 'componentDiffs' array, got: %v", output["componentDiffs"])
	}
	if len(diffs) != 3 {
		t.Errorf("expected 3 component diffs, got %d", len(diffs))
	}

	// Check summary
	summary, ok := output["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'summary' to be a map")
	}
	if total, ok := summary["total"].(float64); !ok || int(total) != 3 {
		t.Errorf("expected total=3, got %v", summary["total"])
	}

	// Check data flow changes in extensions
	extensions, _ := output["extensions"].(map[string]interface{})
	if extensions == nil {
		t.Fatal("expected 'extensions' with data flow changes")
	}
	dataFlowChanges, _ := extensions["dataFlowChanges"].([]interface{})
	if len(dataFlowChanges) == 0 {
		t.Error("expected non-empty dataFlowChanges")
	}
}

// TestDiffCommand_SystemDrift_MatchByComponentId verifies that components are
// matched by componentId even when names differ.
func TestDiffCommand_SystemDrift_MatchByComponentId(t *testing.T) {
	oldSys := map[string]interface{}{
		"name": "Test",
		"components": []interface{}{
			map[string]interface{}{
				"name":        "OldName",
				"type":        "application",
				"componentId": testUUIDSameID,
			},
		},
	}
	newSys := map[string]interface{}{
		"name": "Test",
		"components": []interface{}{
			map[string]interface{}{
				"name":        "NewName",
				"type":        "application",
				"componentId": testUUIDSameID,
			},
		},
	}

	oldPath := writeJSONFixture(t, oldSys)
	newPath := writeJSONFixture(t, newSys)

	stdout, stderr, err := executeCommand("diff", "--json", oldPath, newPath)
	allowExitCode(t, err, stderr)

	var output map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(stdout), &output); jsonErr != nil {
		t.Fatalf("invalid JSON: %v", jsonErr)
	}

	diffs, _ := output["componentDiffs"].([]interface{})
	if len(diffs) != 1 {
		t.Fatalf("expected 1 component diff (matched by ID), got %d", len(diffs))
	}

	// Should use the new name
	first, _ := diffs[0].(map[string]interface{})
	if name, ok := first["name"].(string); !ok || name != "NewName" {
		t.Errorf("expected name='NewName', got %v", first["name"])
	}
}

// TestDiffCommand_SystemDrift_Identical verifies exit code 0 for identical system docs.
func TestDiffCommand_SystemDrift_Identical(t *testing.T) {
	path := writeJSONFixture(t, syntheticSystemOld())

	_, _, err := executeCommand("diff", path, path)
	if err != nil {
		t.Errorf("expected exit 0 for identical system docs, got: %v", err)
	}
}

// TestDiffCommand_SystemDrift_ExitCode verifies exit code 1 when system docs differ.
func TestDiffCommand_SystemDrift_ExitCode(t *testing.T) {
	oldPath := writeJSONFixture(t, syntheticSystemOld())
	newPath := writeJSONFixture(t, syntheticSystemNew())

	_, _, err := executeCommand("diff", oldPath, newPath)
	requireExitCode(t, err, exitcodes.Differences)
}

// TestDiffCommand_SystemDrift_DataFlowChanges verifies data flow diffs are reported.
func TestDiffCommand_SystemDrift_DataFlowChanges(t *testing.T) {
	oldPath := writeJSONFixture(t, syntheticSystemOld())
	newPath := writeJSONFixture(t, syntheticSystemNew())

	stdout, stderr, err := executeCommand("diff", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// Should show data flow detail section
	if !strings.Contains(stdout, "Data Flows:") {
		t.Errorf("expected 'Data Flows:' section in output, got:\n%s", stdout)
	}
	// Should show the updated flow (port changed) and new flow (to cache)
	if !strings.Contains(stdout, testUUIDDatabase) || !strings.Contains(stdout, testUUIDCache) {
		t.Errorf("expected flow endpoints in output, got:\n%s", stdout)
	}
	// Summary should show flow counts
	if !strings.Contains(stdout, "added") {
		t.Errorf("expected 'added' data flow count in output, got:\n%s", stdout)
	}
}

// TestDiffCommand_SystemDrift_NameOnly verifies --name-only shows changed component names.
func TestDiffCommand_SystemDrift_NameOnly(t *testing.T) {
	oldPath := writeJSONFixture(t, syntheticSystemOld())
	newPath := writeJSONFixture(t, syntheticSystemNew())

	stdout, stderr, err := executeCommand("diff", "--name-only", oldPath, newPath)
	allowExitCode(t, err, stderr)

	// WebTier is updated, Database is absent, CacheLayer is new — all should appear
	if !strings.Contains(stdout, "WebTier") {
		t.Errorf("expected 'WebTier' in --name-only output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Database") {
		t.Errorf("expected 'Database' in --name-only output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "CacheLayer") {
		t.Errorf("expected 'CacheLayer' in --name-only output, got:\n%s", stdout)
	}
}

// TestDiffCommand_SystemDrift_Stat verifies --stat shows summary counts for system diffs.
func TestDiffCommand_SystemDrift_Stat(t *testing.T) {
	oldPath := writeJSONFixture(t, syntheticSystemOld())
	newPath := writeJSONFixture(t, syntheticSystemNew())

	stdout, stderr, err := executeCommand("diff", "--stat", oldPath, newPath)
	allowExitCode(t, err, stderr)

	if !strings.Contains(stdout, "1 new") {
		t.Errorf("expected '1 new' in --stat output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 absent") {
		t.Errorf("expected '1 absent' in --stat output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 updated") {
		t.Errorf("expected '1 updated' in --stat output, got:\n%s", stdout)
	}
}

// --- Mixed document type error tests ---

// TestDiffCommand_MismatchedTypes rejects diffing a results doc against a system doc.
func TestDiffCommand_MismatchedTypes(t *testing.T) {
	resultsPath := writeHDFFixture(t, syntheticHDFBefore())
	systemPath := writeJSONFixture(t, syntheticSystemOld())

	_, _, err := executeCommand("diff", resultsPath, systemPath)
	if err == nil {
		t.Fatal("expected error when diffing results against system document")
	}
	if !strings.Contains(err.Error(), "cannot diff") {
		t.Errorf("expected 'cannot diff' error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "same type") {
		t.Errorf("expected 'same type' hint, got: %v", err)
	}
}

// TestDiffCommand_UnsupportedType rejects diffing baseline documents (not yet supported).
func TestDiffCommand_UnsupportedType(t *testing.T) {
	baseline := map[string]interface{}{
		"name":     "test-baseline",
		"checksum": map[string]interface{}{"algorithm": "sha256", "value": "abc"},
		"requirements": []interface{}{
			map[string]interface{}{
				"id": "REQ-1", "impact": 0.5,
				"descriptions": []interface{}{map[string]interface{}{"label": "default", "data": "test"}},
				"tags":         map[string]interface{}{}, "code": "", "refs": []interface{}{},
				"sourceLocation": map[string]interface{}{"line": 1, "ref": "test.rb"},
			},
		},
	}
	path := writeJSONFixture(t, baseline)

	_, _, err := executeCommand("diff", path, path)
	if err == nil {
		t.Fatal("expected error when diffing baseline documents")
	}
	if !strings.Contains(err.Error(), "does not support") {
		t.Errorf("expected 'does not support' error, got: %v", err)
	}
}
