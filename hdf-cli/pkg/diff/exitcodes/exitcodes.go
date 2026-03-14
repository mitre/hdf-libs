// Package exitcodes provides GNU diff compatible and detailed exit codes
// for HDF comparison operations. Basic codes (0/1/2) follow the GNU diff
// convention. Detailed codes (10-14) communicate nuanced security outcomes
// such as fixes, regressions, baseline changes, and metadata drift.
package exitcodes

import types "github.com/mitre/hdf-cli/pkg/diff/types"

// Basic exit codes (GNU diff compatible).
const (
	Identical   = 0
	Differences = 1
	Error       = 2
)

// Detailed exit codes (nuanced security outcomes).
const (
	FixesOnly       = 10
	RegressionsOnly = 11
	Mixed           = 12
	BaselineChanged = 13
	DriftOnly       = 14
)

// ComputeBasicExitCode returns 0 for identical, 1 for any differences.
//
// Note: error (exit code 2) is not computed from the summary — callers
// should return Error directly when I/O or parse errors occur.
func ComputeBasicExitCode(summary types.ComparisonSummary) int {
	if hasDifferences(summary) {
		return Differences
	}
	return Identical
}

// ComputeDetailedExitCode returns a nuanced exit code based on what changed.
//
// Returns:
//
//	0  = identical (no differences found)
//	10 = differences found, fixes only (security posture improved)
//	11 = differences found, regressions only (security posture degraded)
//	12 = differences found, mixed fixes and regressions
//	13 = differences found, only new/absent controls (baseline changed)
//	14 = differences found, only metadata drift (no status changes)
//
// Priority: mixed(12) > regressions(11) > fixes(10) > baseline(13) > drift(14).
func ComputeDetailedExitCode(summary types.ComparisonSummary) int {
	if !hasDifferences(summary) {
		return Identical
	}

	// Mixed: both fixes and regressions.
	if summary.Regressed > 0 && summary.Fixed > 0 {
		return Mixed
	}

	// Regressions only (no fixes).
	if summary.Regressed > 0 {
		return RegressionsOnly
	}

	// Fixes only (no regressions).
	if summary.Fixed > 0 {
		return FixesOnly
	}

	// Baseline changes: new or absent controls (but no status changes).
	if summary.New > 0 || summary.Absent > 0 {
		return BaselineChanged
	}

	// Everything else is metadata drift (updated tags, descriptions, etc.).
	return DriftOnly
}

// hasDifferences returns true if the summary indicates any differences at all.
func hasDifferences(summary types.ComparisonSummary) bool {
	return summary.Total != summary.Unchanged
}
