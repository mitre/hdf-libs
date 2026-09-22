//nolint:dupl
package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Minimal HDF results with known control status/severity distribution.
// 2 passed (1 high, 1 medium), 1 failed (high), 1 notApplicable (impact 0.0).
const testResultsForThreshold = `{
	"baselines": [{
		"name": "threshold-test",
		"requirements": [
			{
				"id": "SV-001",
				"title": "Passed High",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.7,
				"severity": "high",
				"tags": {},
				"results": [{"status": "passed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-002",
				"title": "Passed Medium",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.5,
				"severity": "medium",
				"tags": {},
				"results": [{"status": "passed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-003",
				"title": "Failed High",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.7,
				"severity": "high",
				"tags": {},
				"results": [{"status": "failed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-004",
				"title": "Not Applicable",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.0,
				"tags": {},
				"results": [{"status": "notApplicable", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			}
		],
		"supports": [],
		"groups": []
	}],
	"platform": {"name": "test", "release": "1.0"},
	"statistics": {"duration": 1.0},
	"version": "2.0.0"
}`

// A document with no failed requirement, distinct from testResultsForThreshold
// in baseline name and in every id. Bulk tests need a genuine pass/fail PAIR:
// the same file passed twice cannot distinguish a gate that read both arguments
// from one that read the first and stopped.
const testResultsNoFailures = `{
	"baselines": [{
		"name": "threshold-test-clean",
		"requirements": [
			{
				"id": "SV-101",
				"title": "Passed High",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.7,
				"severity": "high",
				"tags": {},
				"results": [{"status": "passed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-102",
				"title": "Passed Medium",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.5,
				"severity": "medium",
				"tags": {},
				"results": [{"status": "passed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			}
		],
		"supports": [],
		"groups": []
	}],
	"platform": {"name": "test", "release": "1.0"},
	"statistics": {"duration": 1.0},
	"version": "2.0.0"
}`

// writeResultsAt writes a document into a caller-chosen directory under a
// caller-chosen name, so a bulk test controls the ORDER files reach the gate —
// which is the whole property the fail-fast and process-everything tests assert.
func writeResultsAt(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func writeTestResults(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	require.NoError(t, os.WriteFile(path, []byte(testResultsForThreshold), 0o644))
	return path
}

// Impact-0 requirements whose RAW result status is notReviewed, not
// notApplicable — the InSpec skip shape (a skip serialises as a notReviewed
// result; Not Applicable is signalled by impact==0, with an explicit non-zero
// STIG severity tag still present). Raw counting miscounts these as skipped;
// effective-status counting resolves impact==0 to notApplicable (no_impact).
// Effective distribution: 1 passed(high), 1 failed(high), 1 skipped(medium,
// genuine notReviewed at impact 0.5), 2 no_impact(1 high + 1 medium).
const testResultsImpactZeroNotReviewed = `{
	"baselines": [{
		"name": "impact-zero-threshold-test",
		"requirements": [
			{
				"id": "SV-NA-1",
				"title": "NA via impact 0, raw notReviewed, high severity",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.0,
				"severity": "high",
				"tags": {},
				"results": [{"status": "notReviewed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-NA-2",
				"title": "NA via impact 0, raw notReviewed, medium severity",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.0,
				"severity": "medium",
				"tags": {},
				"results": [{"status": "notReviewed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-SKIP",
				"title": "Genuine notReviewed at impact 0.5",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.5,
				"severity": "medium",
				"tags": {},
				"results": [{"status": "notReviewed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-PASS",
				"title": "Passed high",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.7,
				"severity": "high",
				"tags": {},
				"results": [{"status": "passed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-FAIL",
				"title": "Failed high",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.7,
				"severity": "high",
				"tags": {},
				"results": [{"status": "failed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			}
		],
		"supports": [],
		"groups": []
	}],
	"platform": {"name": "test", "release": "1.0"},
	"statistics": {"duration": 1.0},
	"version": "2.0.0"
}`

func writeImpactZeroResults(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	require.NoError(t, os.WriteFile(path, []byte(testResultsImpactZeroNotReviewed), 0o644))
	return path
}

// TestCountByStatusSeverity_ImpactZeroNotReviewedIsNoImpact is the lj0g.8
// regression guard: impact-0 requirements whose raw result status is notReviewed
// must count as no_impact (Not Applicable), never skipped, and must leave the
// compliance denominator. Fails on the pre-fix raw-counting path (which would
// report no_impact.total=0, skipped.total=3, compliance=20%).
func TestCountByStatusSeverity_ImpactZeroNotReviewedIsNoImpact(t *testing.T) {
	data := []byte(testResultsImpactZeroNotReviewed)

	counts, err := countControlsByStatusSeverity(data)
	require.NoError(t, err)

	assert.Equal(t, 2, counts.NoImpact.Total, "impact-0 notReviewed controls are Not Applicable")
	assert.Equal(t, 1, counts.NoImpact.High)
	assert.Equal(t, 1, counts.NoImpact.Medium)
	assert.Equal(t, 1, counts.Skipped.Total, "only the genuine impact>0 notReviewed control is skipped")
	assert.Equal(t, 1, counts.Skipped.Medium)
	assert.Equal(t, 1, counts.Passed.Total)
	assert.Equal(t, 1, counts.Failed.Total)
	assert.Equal(t, 0, counts.Error.Total)

	// Not Applicable leaves the denominator: 1 passed / (1 passed + 1 failed +
	// 1 skipped) = 33.33%, not the raw-path 1/(1+1+3) = 20%.
	compliance := hdfengine.CalculateCompliance(counts)
	assert.InDelta(t, 33.33, compliance, 0.01)
}

// TestThresholdCounting_ParseError covers the parse-failure branch of both
// counting entry points (the CLI's gated pipeline rejecting non-HDF input).
func TestThresholdCounting_ParseError(t *testing.T) {
	_, err := countControlsByStatusSeverity([]byte("not valid hdf"))
	require.Error(t, err)
	_, err = mapControlIDs([]byte("not valid hdf"))
	require.Error(t, err)
}

// TestMapControlIDs_ImpactZeroNotReviewedIsNoImpact guards the per-control
// listing path (used by --include-controls and per-control threshold checks):
// impact-0 notReviewed controls must map to the no_impact key, matching counts.
func TestMapControlIDs_ImpactZeroNotReviewedIsNoImpact(t *testing.T) {
	data := []byte(testResultsImpactZeroNotReviewed)

	mappings, err := mapControlIDs(data)
	require.NoError(t, err)

	byID := map[string]ControlIDMapping{}
	for _, m := range mappings {
		byID[m.ID] = m
	}
	assert.Equal(t, thresholdNoImpact, byID["SV-NA-1"].Status)
	assert.Equal(t, thresholdNoImpact, byID["SV-NA-2"].Status)
	assert.Equal(t, thresholdSkipped, byID["SV-SKIP"].Status)
	assert.Equal(t, thresholdPassed, byID["SV-PASS"].Status)
	assert.Equal(t, thresholdFailed, byID["SV-FAIL"].Status)
}

// TestValidateThreshold_NoImpactSectionIsLive proves the no_impact.* threshold
// section is no longer dead: a no_impact.total bound is satisfiable against a
// document with impact-0 notReviewed controls. On the pre-fix path no_impact was
// always 0, so no_impact.total.min:2 could never pass.
func TestValidateThreshold_NoImpactSectionIsLive(t *testing.T) {
	resultsPath := writeImpactZeroResults(t)

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-I", "{no_impact.total.min: 2}, {skipped.total.max: 1}")
	require.NoError(t, err, "no_impact.total.min:2 and skipped.total.max:1 hold under effective status")
}

// An impact-0 requirement whose scan CRASHED (raw result status error) — the
// impact-0-errored shape. Effective distribution must be 1 error(high), 1
// passed(high); the errored control must never land in no_impact.
const testResultsImpactZeroError = `{
	"baselines": [{
		"name": "impact-zero-error-threshold-test",
		"requirements": [
			{
				"id": "SV-ERR-NA",
				"title": "Crashed check at impact 0",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.0,
				"severity": "high",
				"tags": {},
				"results": [{"status": "error", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SV-PASS",
				"title": "Passed high",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.7,
				"severity": "high",
				"tags": {},
				"results": [{"status": "passed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			}
		],
		"supports": [],
		"groups": []
	}],
	"platform": {"name": "test", "release": "1.0"},
	"statistics": {"duration": 1.0},
	"version": "2.0.0"
}`

// TestCountByStatusSeverity_ImpactZeroErrorIsError pins the impact-0 error escape at the
// threshold counting layer: a crashed check at impact 0 counts under error —
// never no_impact — so error.* threshold gates see it.
func TestCountByStatusSeverity_ImpactZeroErrorIsError(t *testing.T) {
	counts, err := countControlsByStatusSeverity([]byte(testResultsImpactZeroError))
	require.NoError(t, err)

	assert.Equal(t, 1, counts.Error.Total, "impact-0 errored control counts as error")
	assert.Equal(t, 1, counts.Error.High)
	assert.Equal(t, 0, counts.NoImpact.Total, "the crashed check must not be Not Applicable")
	assert.Equal(t, 1, counts.Passed.Total)
}

// TestValidateThreshold_ImpactZeroErrorTripsErrorGate proves the CLI-level
// consequence of the impact-0 error escape: `hdf validate threshold -I "{error.total.max: 0}"`
// must FAIL on a document whose only defect is a crashed impact-0 check. On the
// pre-fix path the error landed in no_impact and the gate passed silently.
func TestValidateThreshold_ImpactZeroErrorTripsErrorGate(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "results.json")
	require.NoError(t, os.WriteFile(resultsPath, []byte(testResultsImpactZeroError), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-I", "{error.total.max: 0}")
	require.Error(t, err, "error.total.max:0 must fail on a crashed impact-0 check")
}

// --- Counting logic tests ---

func TestCountByStatusSeverity(t *testing.T) {
	resultsPath := writeTestResults(t)
	data, err := os.ReadFile(resultsPath)
	require.NoError(t, err)

	counts, err := countControlsByStatusSeverity(data)
	require.NoError(t, err)

	assert.Equal(t, 2, counts.Passed.Total)
	assert.Equal(t, 1, counts.Passed.High)
	assert.Equal(t, 1, counts.Passed.Medium)
	assert.Equal(t, 1, counts.Failed.Total)
	assert.Equal(t, 1, counts.Failed.High)
	assert.Equal(t, 1, counts.NoImpact.Total)
	assert.Equal(t, 0, counts.Skipped.Total)
	assert.Equal(t, 0, counts.Error.Total)
}

func TestCalculateCompliance(t *testing.T) {
	// 2 passed / (2 passed + 1 failed + 0 skipped + 0 error) = 66.67%
	counts := &StatusCounts{
		Passed: SeverityCounts{Total: 2},
		Failed: SeverityCounts{Total: 1},
	}
	compliance := hdfengine.CalculateCompliance(counts)
	assert.InDelta(t, 66.67, compliance, 0.01)
}

func TestCalculateCompliance_AllPassed(t *testing.T) {
	counts := &StatusCounts{
		Passed: SeverityCounts{Total: 10},
	}
	assert.Equal(t, 100.0, hdfengine.CalculateCompliance(counts))
}

func TestCalculateCompliance_NoneRelevant(t *testing.T) {
	counts := &StatusCounts{
		NoImpact: SeverityCounts{Total: 5},
	}
	assert.Equal(t, 0.0, hdfengine.CalculateCompliance(counts))
}

// --- Generate threshold tests ---

func TestGenerateThreshold_BasicUsage(t *testing.T) {
	resultsPath := writeTestResults(t)
	outputDir := t.TempDir()
	thresholdPath := filepath.Join(outputDir, "threshold.yaml")

	_, _, err := executeCommand("generate", "threshold", resultsPath, "-o", thresholdPath)
	require.NoError(t, err)

	content, err := os.ReadFile(thresholdPath)
	require.NoError(t, err)
	yaml := string(content)

	// Default (non-exact) mode: passed gets min, failed gets max
	assert.Contains(t, yaml, "compliance:")
	assert.Contains(t, yaml, "passed:")
	assert.Contains(t, yaml, "failed:")
}

func TestGenerateThreshold_Stdout(t *testing.T) {
	resultsPath := writeTestResults(t)

	stdout, _, err := executeCommand("generate", "threshold", resultsPath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "compliance:")
}

func TestGenerateThreshold_Exact(t *testing.T) {
	resultsPath := writeTestResults(t)

	stdout, _, err := executeCommand("generate", "threshold", resultsPath, "--exact")
	require.NoError(t, err)

	// Exact mode: all counts get both min and max
	assert.Contains(t, stdout, "min:")
	assert.Contains(t, stdout, "max:")
}

// --- Validate threshold tests ---

func TestValidateThreshold_Passing(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	// Lenient threshold that should pass
	threshold := `
compliance:
  min: 50
passed:
  total:
    min: 1
failed:
  total:
    max: 5
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	assert.NoError(t, err)
}

func TestValidateThreshold_FailingCompliance(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	// Require 90% compliance but we only have ~66%
	threshold := `
compliance:
  min: 90
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "compliance")
}

func TestValidateThreshold_FailingMaxFailed(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	// Zero-fail policy for high severity
	threshold := `
failed:
  high:
    max: 0
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed.high")
}

func TestValidateThreshold_MissingTemplate(t *testing.T) {
	resultsPath := writeTestResults(t)

	_, _, err := executeCommand("validate", "threshold", resultsPath)
	assert.Error(t, err)
}

func TestGenerateThreshold_IncludeControls(t *testing.T) {
	resultsPath := writeTestResults(t)

	stdout, _, err := executeCommand("generate", "threshold", resultsPath, "--include-controls")
	require.NoError(t, err)

	// Should contain control ID lists
	assert.Contains(t, stdout, "controls:")
	assert.Contains(t, stdout, "SV-001")
	assert.Contains(t, stdout, "SV-002")
	assert.Contains(t, stdout, "SV-003")
}

func TestValidateThreshold_ControlIDPassing(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	// Threshold expects SV-001 to be passed/high
	threshold := `
passed:
  high:
    controls:
      - SV-001
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	assert.NoError(t, err)
}

func TestValidateThreshold_ControlIDFailing(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	// Threshold expects SV-003 to be passed, but it's actually failed
	threshold := `
passed:
  high:
    controls:
      - SV-003
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SV-003")
}

func TestValidateThreshold_RoundTrip(t *testing.T) {
	// Generate a threshold from results, then validate the same results against it.
	// This should always pass.
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	_, _, err := executeCommand("generate", "threshold", resultsPath, "-o", thresholdFile)
	require.NoError(t, err)

	_, _, err = executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	assert.NoError(t, err)
}

func TestValidateThreshold_RoundTripWithControls(t *testing.T) {
	// Same round-trip but with control IDs included.
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	_, _, err := executeCommand("generate", "threshold", resultsPath, "--include-controls", "-o", thresholdFile)
	require.NoError(t, err)

	_, _, err = executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	assert.NoError(t, err)
}

func TestValidateThreshold_InlinePassing(t *testing.T) {
	resultsPath := writeTestResults(t)

	_, _, err := executeCommand("validate", "threshold", resultsPath,
		"-I", "{compliance.min: 50}, {passed.total.min: 1}, {failed.total.max: 5}")
	assert.NoError(t, err)
}

func TestValidateThreshold_InlineFailing(t *testing.T) {
	resultsPath := writeTestResults(t)

	// Require 90% compliance but we only have ~66%
	_, _, err := executeCommand("validate", "threshold", resultsPath,
		"-I", "{compliance.min: 90}")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "compliance")
}

func TestValidateThreshold_InlineZeroFail(t *testing.T) {
	resultsPath := writeTestResults(t)

	// Zero-fail policy for high severity
	_, _, err := executeCommand("validate", "threshold", resultsPath,
		"-I", "{failed.high.max: 0}")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed.high")
}

func TestValidateThreshold_InlineAndTemplateMutuallyExclusive(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")
	require.NoError(t, os.WriteFile(thresholdFile, []byte("compliance:\n  min: 50\n"), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath,
		"-T", thresholdFile, "-I", "{compliance.min: 50}")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestGenerateThreshold_MissingInput(t *testing.T) {
	_, _, err := executeCommand("generate", "threshold")
	assert.Error(t, err)
}

// A misspelled key in a template file must be rejected. Permissive parsing
// silently drops unknown keys, so a typo yields an empty threshold set that
// passes vacuously — a committed gate that asserts nothing while reporting
// success. Each nesting level fails independently, so each is covered.
func TestValidateThreshold_RejectsUnknownCategory(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	// "faild" instead of "failed": the real template would fail this document.
	threshold := `
faild:
  total:
    max: 0
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "faild")
}

func TestValidateThreshold_RejectsUnknownSeverityField(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	threshold := `
failed:
  totl:
    max: 0
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "totl")
}

func TestValidateThreshold_RejectsUnknownBound(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	threshold := `
failed:
  total:
    mx: 0
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mx")
}

// The committed pipeline templates must survive the stricter parse — a
// strictness change that breaks a real gate template is a regression.
func TestValidateThreshold_AcceptsEveryKnownKey(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")

	threshold := `
compliance:
  min: 0
  max: 100
passed:
  critical: { min: 0 }
  high: { min: 0 }
  medium: { min: 0 }
  low: { min: 0 }
  none: { min: 0 }
  total: { min: 0 }
failed:
  total: { max: 1000 }
skipped:
  total: { max: 1000 }
error:
  total: { max: 1000 }
no_impact:
  total: { max: 1000 }
`
	require.NoError(t, os.WriteFile(thresholdFile, []byte(threshold), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	assert.NoError(t, err)
}

// A template asserting nothing passes every document, which is the same false
// green a misspelled key used to produce — strict parsing closes the typo route
// in, so this closes the deliberate one.
func TestValidateThreshold_RejectsTemplateAssertingNothing(t *testing.T) {
	resultsPath := writeTestResults(t)

	for name, body := range map[string]string{
		"empty file":    "",
		"empty mapping": "{}\n",
		"comment only":  "# no thresholds here\n",
		"empty section": "failed: {}\n",
		"empty bound":   "failed:\n  total: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")
			require.NoError(t, os.WriteFile(thresholdFile, []byte(body), 0o644))

			_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "asserts nothing")
		})
	}
}

// The rejection must read in the template's own vocabulary rather than leaking
// the Go type that happened to reject the key.
func TestValidateThreshold_UnknownKeyErrorAvoidsGoTypeNames(t *testing.T) {
	resultsPath := writeTestResults(t)
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")
	require.NoError(t, os.WriteFile(thresholdFile, []byte("faild:\n  total:\n    max: 0\n"), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-T", thresholdFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not a known threshold category")
	assert.NotContains(t, err.Error(), "hdfengine.")
}

// The inline path buckets an unrecognized severity into "none" via
// getSeverityBound, which is correct when generate places a scan's own severity
// but wrong for a user-typed path: the typo asserted a bound nobody asked for
// and passed silently, the same failure the template path had.
func TestValidateThreshold_InlineRejectsUnknownSeverityField(t *testing.T) {
	resultsPath := writeTestResults(t)

	for _, path := range []string{"failed.totl.max", "failed.hgh.max", "passed.criticl.min"} {
		t.Run(path, func(t *testing.T) {
			_, _, err := executeCommand("validate", "threshold", resultsPath, "-I", "{"+path+": 0}")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unknown severity field")
		})
	}
}

func TestValidateThreshold_InlineAcceptsEverySeverityField(t *testing.T) {
	resultsPath := writeTestResults(t)

	for _, path := range []string{"failed.critical.max", "failed.high.max", "failed.medium.max", "failed.low.max", "failed.none.max", "failed.total.max"} {
		t.Run(path, func(t *testing.T) {
			// A generous bound: the point is that the path parses, not the verdict.
			_, _, err := executeCommand("validate", "threshold", resultsPath, "-I", "{"+path+": 1000}")
			assert.NoError(t, err)
		})
	}
}

// A gate applies one policy to a directory of documents, so the command must
// take more than one file — `convert` and `validate` already do. The template
// is parsed once and applied per file.
func TestValidateThreshold_AcceptsMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	first := writeResultsAt(t, dir, "first.json", testResultsForThreshold)
	second := writeResultsAt(t, dir, "second.json", testResultsNoFailures)
	thresholdFile := writeResultsAt(t, dir, "threshold.yaml", "failed:\n  total:\n    max: 5\n")

	_, stderr, err := executeCommand("validate", "threshold", first, second, "-T", thresholdFile)
	assert.NoError(t, err)
	// Distinct files, both named in the output: passing the same path twice
	// cannot tell a gate that read both from one that read the first and stopped.
	assert.Contains(t, stderr, first)
	assert.Contains(t, stderr, second)
}

// One failing document among several must fail the whole invocation — a gate
// that passes because most files were fine is not a gate.
func TestValidateThreshold_MultipleFilesFailIfAnyViolates(t *testing.T) {
	dir := t.TempDir()
	clean := writeResultsAt(t, dir, "clean.json", testResultsNoFailures)
	violating := writeResultsAt(t, dir, "violating.json", testResultsForThreshold)
	thresholdFile := writeResultsAt(t, dir, "threshold.yaml", "failed:\n  total:\n    max: 0\n")

	// The mixed case the name describes: one document passes, one does not.
	// Two violating files would fail whatever the loop did with either.
	for name, order := range map[string][]string{
		"violator first": {violating, clean},
		"violator last":  {clean, violating},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := executeCommand(append(append([]string{"validate", "threshold"}, order...), "-T", thresholdFile)...)
			require.Error(t, err, "one violating document must fail the whole invocation")
		})
	}
}

// The default is POSIX-style: process every file, report at the end. A gate that
// stopped at the first violation would hide every later one, so a contributor
// would fix one finding per CI run.
func TestValidateThreshold_ProcessesEveryFileByDefault(t *testing.T) {
	dir := t.TempDir()
	violating := writeResultsAt(t, dir, "violating.json", testResultsForThreshold)
	clean := writeResultsAt(t, dir, "clean.json", testResultsNoFailures)
	thresholdFile := writeResultsAt(t, dir, "threshold.yaml", "failed:\n  total:\n    max: 0\n")

	_, stderr, err := executeCommand("validate", "threshold", violating, clean, "-T", thresholdFile)
	require.Error(t, err, "the violating document must still fail the run")
	assert.Contains(t, stderr, clean+": ok", "the file after the violation must still be processed")
}

// -F is the opposite contract, and it is the one a slow pipeline relies on.
func TestValidateThreshold_FailFastStopsAtTheFirstViolation(t *testing.T) {
	dir := t.TempDir()
	violating := writeResultsAt(t, dir, "violating.json", testResultsForThreshold)
	clean := writeResultsAt(t, dir, "clean.json", testResultsNoFailures)
	thresholdFile := writeResultsAt(t, dir, "threshold.yaml", "failed:\n  total:\n    max: 0\n")

	_, stderr, err := executeCommand("validate", "threshold", violating, clean, "-T", thresholdFile, "-F")
	require.Error(t, err)
	assert.NotContains(t, stderr, clean, "with -F the run must abort before reaching the second file")
}

// Zero files must be an error, not a vacuous pass: an unmatched shell glob
// reaching the gate has to fail closed.
func TestValidateThreshold_RejectsNoFiles(t *testing.T) {
	thresholdFile := filepath.Join(t.TempDir(), "threshold.yaml")
	require.NoError(t, os.WriteFile(thresholdFile, []byte("failed:\n  total:\n    max: 0\n"), 0o644))

	_, _, err := executeCommand("validate", "threshold", "-T", thresholdFile)
	require.Error(t, err)
}

// testResultsEverySchemaSeverity carries one requirement per value of the
// schema's severity enum (critical|high|medium|low|informational) plus one with
// no severity at all, whose severity derives from impact. Every value the schema
// permits must survive generate -> validate.
const testResultsEverySchemaSeverity = `{
	"baselines": [{
		"name": "severity-roundtrip",
		"requirements": [
			{
				"id": "SEV-CRITICAL",
				"title": "critical",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.95,
				"severity": "critical",
				"tags": {},
				"results": [{"status": "failed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SEV-HIGH",
				"title": "high",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.7,
				"severity": "high",
				"tags": {},
				"results": [{"status": "failed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SEV-MEDIUM",
				"title": "medium",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.5,
				"severity": "medium",
				"tags": {},
				"results": [{"status": "passed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SEV-LOW",
				"title": "low",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.3,
				"severity": "low",
				"tags": {},
				"results": [{"status": "passed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SEV-INFORMATIONAL",
				"title": "explicit informational",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.0,
				"severity": "informational",
				"tags": {},
				"results": [{"status": "notReviewed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			},
			{
				"id": "SEV-DERIVED",
				"title": "no severity field; derives from impact 0",
				"descriptions": [{"label": "default", "data": "test"}],
				"impact": 0.0,
				"tags": {},
				"results": [{"status": "notReviewed", "codeDesc": "check", "startTime": "2024-01-01T00:00:00Z"}]
			}
		]
	}]
}`

// A generated template must validate the document it was generated from. This
// pins the round-trip regression: generate bucketed severities through
// getSeverityBound while validate compared the raw severity string, so an
// explicit "informational" produced
// "expected no_impact/none but found no_impact/informational".
func TestThresholdRoundTrip_EverySchemaSeverity(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "results.json")
	require.NoError(t, os.WriteFile(resultsPath, []byte(testResultsEverySchemaSeverity), 0o644))
	thresholdPath := filepath.Join(dir, "t.yaml")

	_, _, err := executeCommand("generate", "threshold", resultsPath, "--include-controls", "--exact", "-o", thresholdPath)
	require.NoError(t, err)

	_, _, err = executeCommand("validate", "threshold", resultsPath, "-T", thresholdPath)
	require.NoError(t, err, "a generated template must validate its own document")
}

// An explicitly informational requirement is reported under informational — the
// schema's value — not folded into a bucket the schema does not define.
func TestThresholdCounting_InformationalIsItsOwnBucket(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "results.json")
	require.NoError(t, os.WriteFile(resultsPath, []byte(testResultsEverySchemaSeverity), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-I", "{no_impact.informational.min: 2}")
	require.NoError(t, err, "both the explicit and the impact-derived informational must land in informational")
}

// A severity outside the schema enum never reaches the counting layer: the
// schema validator rejects the document at load, naming the field and the legal
// values. Pinned because the engine's own bucketing has a catch-all for this
// case, and it would be easy to assume the CLI exercises it.
func TestThresholdCounting_MalformedSeverityRejectedAtLoad(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "results.json")
	malformed := strings.Replace(testResultsEverySchemaSeverity, `"severity": "low"`, `"severity": "sev-9"`, 1)
	require.NoError(t, os.WriteFile(resultsPath, []byte(malformed), 0o644))

	_, _, err := executeCommand("generate", "threshold", resultsPath, "--include-controls", "-o", filepath.Join(dir, "t.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "severity")
	assert.Contains(t, err.Error(), "informational", "the error must name the legal values")
}

// Templates this tool generated before the fold was removed say "none". They
// meant the controls that now count as informational, so the key keeps working.
func TestValidateThreshold_LegacyNoneKeyIsAcceptedAsInformational(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "results.json")
	require.NoError(t, os.WriteFile(resultsPath, []byte(testResultsEverySchemaSeverity), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath, "-I", "{no_impact.none.min: 2}")
	require.NoError(t, err, "legacy none: must still resolve")
}

// The inline path must route the legacy spelling to the legacy field, not fold
// it early — otherwise a spec naming both writes them to one pointer and the
// second silently overwrites the first instead of being refused.
func TestValidateThreshold_InlineBothSpellingsIsRefused(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "results.json")
	require.NoError(t, os.WriteFile(resultsPath, []byte(testResultsEverySchemaSeverity), 0o644))

	_, _, err := executeCommand("validate", "threshold", resultsPath,
		"-I", "{no_impact.none.max: 1}, {no_impact.informational.max: 2}")
	require.Error(t, err, "a spec naming one bucket twice must be refused, not silently resolved")
	assert.Contains(t, err.Error(), "pre-3.7 spelling")
}
