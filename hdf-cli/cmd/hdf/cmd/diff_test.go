package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
		"targets":    []interface{}{},
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
		"targets":    []interface{}{},
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
		"targets":    []interface{}{},
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
		"targets":    []interface{}{},
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
		"targets":    []interface{}{},
		"statistics": map[string]interface{}{},
	}
}

// TestDiffCommand_BasicComparison verifies that the diff command correctly
// classifies requirements as fixed, regressed, unchanged, new, and absent.
func TestDiffCommand_BasicComparison(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", oldPath, newPath)
	if err != nil {
		t.Fatalf("diff command failed: %v (stderr: %s)", err, stderr)
	}

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
	if err != nil {
		t.Fatalf("diff command failed: %v (stderr: %s)", err, stderr)
	}

	// All 4 requirements should be unchanged
	if !strings.Contains(stdout, "4 unchanged") {
		t.Errorf("expected '4 unchanged' in output, got:\n%s", stdout)
	}

	// Should have no fixed, regressed, new, or absent
	if strings.Contains(stdout, "fixed") && !strings.Contains(stdout, "0 fixed") {
		t.Errorf("expected 0 fixed in output, got:\n%s", stdout)
	}
}

// TestDiffCommand_JSONOutput verifies that --json produces valid JSON with the correct structure.
func TestDiffCommand_JSONOutput(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	stdout, stderr, err := executeCommand("diff", "--json", oldPath, newPath)
	if err != nil {
		t.Fatalf("diff command failed: %v (stderr: %s)", err, stderr)
	}

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
	if _, ok := output["requirements"]; !ok {
		t.Error("expected 'requirements' key in JSON output")
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
	reqs, ok := output["requirements"].([]interface{})
	if !ok {
		t.Fatal("expected 'requirements' to be an array")
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
	if err != nil {
		t.Fatalf("diff command failed: %v (stderr: %s)", err, stderr)
	}

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
	if err != nil {
		t.Fatalf("diff command failed: %v (stderr: %s)", err, stderr)
	}

	// Should show REQ-002 (regressed)
	if !strings.Contains(stdout, "REQ-002") {
		t.Errorf("expected REQ-002 in --regressed output, got:\n%s", stdout)
	}

	// Should NOT show fixed
	if strings.Contains(stdout, "REQ-001") {
		t.Errorf("--regressed should not show REQ-001 (fixed), got:\n%s", stdout)
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

// TestDiffCommand_ExitCode_Differences verifies that --exit-code returns exit code 1
// when any differences exist (GNU diff compatible behavior).
func TestDiffCommand_ExitCode_Differences(t *testing.T) {
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	_, _, err := executeCommand("diff", "--exit-code", oldPath, newPath)
	requireExitCode(t, err, exitDifferences)
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
	requireExitCode(t, err, exitDifferences)
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
	requireExitCode(t, err, exitFixesOnly)
}

// TestDiffCommand_DetailedExitCode_RegressionsOnly verifies regressions-only → exit 11.
func TestDiffCommand_DetailedExitCode_RegressionsOnly(t *testing.T) {
	// passed → failed = regression
	oldPath := writeHDFFixture(t, syntheticHDFSinglePassed())
	newPath := writeHDFFixture(t, syntheticHDFSingleFailed())

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitRegressionsOnly)
}

// TestDiffCommand_DetailedExitCode_Mixed verifies mixed fixes+regressions → exit 12.
func TestDiffCommand_DetailedExitCode_Mixed(t *testing.T) {
	// syntheticHDFBefore → syntheticHDFAfter has both fixes and regressions:
	// REQ-001: failed→passed (fixed), REQ-002: passed→failed (regressed)
	oldPath := writeHDFFixture(t, syntheticHDFBefore())
	newPath := writeHDFFixture(t, syntheticHDFAfter())

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitMixed)
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
		"targets":    []interface{}{},
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
		"targets":    []interface{}{},
		"statistics": map[string]interface{}{},
	}

	oldPath := writeHDFFixture(t, oldFixture)
	newPath := writeHDFFixture(t, newFixture)

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitBaselineChanged)
}

// TestDiffCommand_DetailedExitCode_DriftOnly verifies metadata-only changes → exit 14.
func TestDiffCommand_DetailedExitCode_DriftOnly(t *testing.T) {
	// REQ-001 failed→notReviewed is classified as "updated" (not fixed or regressed).
	// No new/absent controls → drift only.
	oldPath := writeHDFFixture(t, syntheticHDFSingleFailed())
	newPath := writeHDFFixture(t, syntheticHDFUpdated())

	_, _, err := executeCommand("diff", "--detailed-exitcode", oldPath, newPath)
	requireExitCode(t, err, exitDriftOnly)
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
	if err != nil {
		t.Fatalf("diff command with --format markdown failed: %v (stderr: %s)", err, stderr)
	}

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
	if err != nil {
		t.Fatalf("diff command failed: %v (stderr: %s)", err, stderr)
	}

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
	if err != nil {
		t.Fatalf("diff command failed: %v (stderr: %s)", err, stderr)
	}

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
	if err != nil {
		t.Fatalf("diff command failed: %v (stderr: %s)", err, stderr)
	}

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
		summary diffSummary
		want    int
	}{
		{"identical", diffSummary{Total: 10, Unchanged: 10}, exitIdentical},
		{"empty", diffSummary{Total: 0, Unchanged: 0}, exitIdentical},
		{"fixes", diffSummary{Total: 10, Fixed: 3, Unchanged: 7}, exitDifferences},
		{"regressions", diffSummary{Total: 10, Regressed: 2, Unchanged: 8}, exitDifferences},
		{"mixed", diffSummary{Total: 10, Fixed: 1, Regressed: 1, Unchanged: 8}, exitDifferences},
		{"new only", diffSummary{Total: 12, New: 2, Unchanged: 10}, exitDifferences},
		{"absent only", diffSummary{Total: 10, Absent: 3, Unchanged: 7}, exitDifferences},
		{"updated only", diffSummary{Total: 10, Updated: 1, Unchanged: 9}, exitDifferences},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeBasicExitCode(tt.summary)
			if got != tt.want {
				t.Errorf("computeBasicExitCode(%v) = %d, want %d", tt.summary, got, tt.want)
			}
		})
	}
}

// TestComputeDetailedExitCode verifies the detailed exit code classification.
func TestComputeDetailedExitCode(t *testing.T) {
	tests := []struct {
		name    string
		summary diffSummary
		want    int
	}{
		{"identical", diffSummary{Total: 10, Unchanged: 10}, exitIdentical},
		{"empty", diffSummary{Total: 0, Unchanged: 0}, exitIdentical},
		{"fixes only", diffSummary{Total: 10, Fixed: 3, Unchanged: 7}, exitFixesOnly},
		{"regressions only", diffSummary{Total: 10, Regressed: 2, Unchanged: 8}, exitRegressionsOnly},
		{"mixed", diffSummary{Total: 10, Fixed: 2, Regressed: 1, Unchanged: 7}, exitMixed},
		{"new only", diffSummary{Total: 12, New: 2, Unchanged: 10}, exitBaselineChanged},
		{"absent only", diffSummary{Total: 10, Absent: 3, Unchanged: 7}, exitBaselineChanged},
		{"new and absent", diffSummary{Total: 10, New: 1, Absent: 1, Unchanged: 8}, exitBaselineChanged},
		{"updated only (drift)", diffSummary{Total: 10, Updated: 1, Unchanged: 9}, exitDriftOnly},
		{"fixes + new (fixes take priority)", diffSummary{Total: 10, Fixed: 2, New: 1, Unchanged: 7}, exitFixesOnly},
		{"regressions + absent (regressions take priority)", diffSummary{Total: 10, Regressed: 1, Absent: 2, Unchanged: 7}, exitRegressionsOnly},
		{"all categories present", diffSummary{Total: 10, Fixed: 1, Regressed: 1, New: 1, Absent: 1, Unchanged: 6}, exitMixed},
		{"updated + new (baseline takes priority over drift)", diffSummary{Total: 10, Updated: 1, New: 1, Unchanged: 8}, exitBaselineChanged},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeDetailedExitCode(tt.summary)
			if got != tt.want {
				t.Errorf("computeDetailedExitCode(%v) = %d, want %d", tt.summary, got, tt.want)
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
