package diff

// ComputeSummary computes aggregate counts from requirement diffs.
func ComputeSummary(requirements []RequirementDiff) ComparisonSummary {
	summary := ComparisonSummary{Total: len(requirements)}

	for _, req := range requirements {
		switch req.State {
		case StateFixed:
			summary.Fixed++
			summary.MatchedCount++
		case StateRegressed:
			summary.Regressed++
			summary.MatchedCount++
		case StateNew:
			summary.New++
			summary.UnmatchedNewCount++
		case StateAbsent:
			summary.Absent++
			summary.UnmatchedOldCount++
		case StateUnchanged:
			summary.Unchanged++
			summary.MatchedCount++
		case StateUpdated:
			summary.Updated++
			summary.MatchedCount++
		case StateMoved, StateSplit, StateMerged:
			// Reserved for v1.1 — no-op in summary counting.
			summary.MatchedCount++
		}
	}

	return summary
}
