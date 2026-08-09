//nolint:dupl
package cmd

import (
	"os"
	"path/filepath"
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
