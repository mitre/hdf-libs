// Package summary computes aggregate counts from requirement diffs.
package summary

import (
	types "github.com/mitre/hdf-cli/pkg/diff/types"
)

// ComputeSummary computes aggregate counts from requirement diffs.
func ComputeSummary(requirements []types.RequirementDiff) types.ComparisonSummary {
	summary := types.ComparisonSummary{Total: len(requirements)}

	for _, req := range requirements {
		switch req.State {
		case types.StateFixed:
			summary.Fixed++
			summary.MatchedCount++
		case types.StateRegressed:
			summary.Regressed++
			summary.MatchedCount++
		case types.StateNew:
			summary.New++
			summary.UnmatchedNewCount++
		case types.StateAbsent:
			summary.Absent++
			summary.UnmatchedOldCount++
		case types.StateUnchanged:
			summary.Unchanged++
			summary.MatchedCount++
		case types.StateUpdated:
			summary.Updated++
			summary.MatchedCount++
		case types.StateMoved, types.StateSplit, types.StateMerged:
			// Reserved for v1.1 — no-op in summary counting.
			summary.MatchedCount++
		}
	}

	return summary
}
