package diff

import (
	"testing"
)

// makeReq builds a minimal RequirementDiff with only the fields ComputeSummary needs.
func makeReq(id string, state RequirementState) RequirementDiff {
	return RequirementDiff{
		ID:            id,
		State:         state,
		ChangeReasons: []ChangeReason{},
		FieldChanges:  []FieldChange{},
	}
}

func TestComputeSummary(t *testing.T) {
	tests := []struct {
		name     string
		reqs     []RequirementDiff
		expected ComparisonSummary
	}{
		{
			name: "empty array returns all zeros",
			reqs: []RequirementDiff{},
			expected: ComparisonSummary{
				Fixed:             0,
				Regressed:         0,
				New:               0,
				Absent:            0,
				Unchanged:         0,
				Updated:           0,
				Total:             0,
				MatchedCount:      0,
				UnmatchedOldCount: 0,
				UnmatchedNewCount: 0,
			},
		},
		{
			name: "all fixed requirements",
			reqs: []RequirementDiff{
				makeReq("SV-001", StateFixed),
				makeReq("SV-002", StateFixed),
				makeReq("SV-003", StateFixed),
			},
			expected: ComparisonSummary{
				Fixed:             3,
				Regressed:         0,
				New:               0,
				Absent:            0,
				Unchanged:         0,
				Updated:           0,
				Total:             3,
				MatchedCount:      3,
				UnmatchedOldCount: 0,
				UnmatchedNewCount: 0,
			},
		},
		{
			name: "all regressed requirements",
			reqs: []RequirementDiff{
				makeReq("SV-001", StateRegressed),
				makeReq("SV-002", StateRegressed),
				makeReq("SV-003", StateRegressed),
				makeReq("SV-004", StateRegressed),
			},
			expected: ComparisonSummary{
				Fixed:             0,
				Regressed:         4,
				New:               0,
				Absent:            0,
				Unchanged:         0,
				Updated:           0,
				Total:             4,
				MatchedCount:      4,
				UnmatchedOldCount: 0,
				UnmatchedNewCount: 0,
			},
		},
		{
			name: "mixed states",
			reqs: []RequirementDiff{
				makeReq("SV-001", StateFixed),
				makeReq("SV-002", StateFixed),
				makeReq("SV-003", StateRegressed),
				makeReq("SV-004", StateUnchanged),
				makeReq("SV-005", StateUnchanged),
				makeReq("SV-006", StateUnchanged),
				makeReq("SV-007", StateNew),
				makeReq("SV-008", StateAbsent),
				makeReq("SV-009", StateUpdated),
			},
			expected: ComparisonSummary{
				Fixed:             2,
				Regressed:         1,
				New:               1,
				Absent:            1,
				Unchanged:         3,
				Updated:           1,
				Total:             9,
				MatchedCount:      7, // fixed(2) + regressed(1) + unchanged(3) + updated(1)
				UnmatchedOldCount: 1, // absent(1)
				UnmatchedNewCount: 1, // new(1)
			},
		},
		{
			name: "single unchanged requirement",
			reqs: []RequirementDiff{
				makeReq("SV-001", StateUnchanged),
			},
			expected: ComparisonSummary{
				Fixed:             0,
				Regressed:         0,
				New:               0,
				Absent:            0,
				Unchanged:         1,
				Updated:           0,
				Total:             1,
				MatchedCount:      1,
				UnmatchedOldCount: 0,
				UnmatchedNewCount: 0,
			},
		},
		{
			name: "all new requirements",
			reqs: []RequirementDiff{
				makeReq("SV-001", StateNew),
				makeReq("SV-002", StateNew),
				makeReq("SV-003", StateNew),
				makeReq("SV-004", StateNew),
				makeReq("SV-005", StateNew),
			},
			expected: ComparisonSummary{
				Fixed:             0,
				Regressed:         0,
				New:               5,
				Absent:            0,
				Unchanged:         0,
				Updated:           0,
				Total:             5,
				MatchedCount:      0,
				UnmatchedOldCount: 0,
				UnmatchedNewCount: 5,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeSummary(tc.reqs)

			if got.Fixed != tc.expected.Fixed {
				t.Errorf("Fixed: got %d, want %d", got.Fixed, tc.expected.Fixed)
			}
			if got.Regressed != tc.expected.Regressed {
				t.Errorf("Regressed: got %d, want %d", got.Regressed, tc.expected.Regressed)
			}
			if got.New != tc.expected.New {
				t.Errorf("New: got %d, want %d", got.New, tc.expected.New)
			}
			if got.Absent != tc.expected.Absent {
				t.Errorf("Absent: got %d, want %d", got.Absent, tc.expected.Absent)
			}
			if got.Unchanged != tc.expected.Unchanged {
				t.Errorf("Unchanged: got %d, want %d", got.Unchanged, tc.expected.Unchanged)
			}
			if got.Updated != tc.expected.Updated {
				t.Errorf("Updated: got %d, want %d", got.Updated, tc.expected.Updated)
			}
			if got.Total != tc.expected.Total {
				t.Errorf("Total: got %d, want %d", got.Total, tc.expected.Total)
			}
			if got.MatchedCount != tc.expected.MatchedCount {
				t.Errorf("MatchedCount: got %d, want %d", got.MatchedCount, tc.expected.MatchedCount)
			}
			if got.UnmatchedOldCount != tc.expected.UnmatchedOldCount {
				t.Errorf("UnmatchedOldCount: got %d, want %d", got.UnmatchedOldCount, tc.expected.UnmatchedOldCount)
			}
			if got.UnmatchedNewCount != tc.expected.UnmatchedNewCount {
				t.Errorf("UnmatchedNewCount: got %d, want %d", got.UnmatchedNewCount, tc.expected.UnmatchedNewCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Coverage: moved, split, merged states (reserved v1.1 branch)
// ---------------------------------------------------------------------------

func TestComputeSummary_MovedSplitMerged(t *testing.T) {
	tests := []struct {
		name  string
		state RequirementState
	}{
		{"moved", StateMoved},
		{"split", StateSplit},
		{"merged", StateMerged},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqs := []RequirementDiff{
				makeReq("SV-001", tc.state),
			}
			got := ComputeSummary(reqs)

			if got.Total != 1 {
				t.Errorf("Total: got %d, want 1", got.Total)
			}
			if got.MatchedCount != 1 {
				t.Errorf("MatchedCount: got %d, want 1 (moved/split/merged are matched)", got.MatchedCount)
			}
			// None of the named counters should be incremented
			if got.Fixed != 0 {
				t.Errorf("Fixed: got %d, want 0", got.Fixed)
			}
			if got.Regressed != 0 {
				t.Errorf("Regressed: got %d, want 0", got.Regressed)
			}
			if got.New != 0 {
				t.Errorf("New: got %d, want 0", got.New)
			}
			if got.Absent != 0 {
				t.Errorf("Absent: got %d, want 0", got.Absent)
			}
			if got.Unchanged != 0 {
				t.Errorf("Unchanged: got %d, want 0", got.Unchanged)
			}
			if got.Updated != 0 {
				t.Errorf("Updated: got %d, want 0", got.Updated)
			}
			if got.UnmatchedOldCount != 0 {
				t.Errorf("UnmatchedOldCount: got %d, want 0", got.UnmatchedOldCount)
			}
			if got.UnmatchedNewCount != 0 {
				t.Errorf("UnmatchedNewCount: got %d, want 0", got.UnmatchedNewCount)
			}
		})
	}
}

func TestComputeSummary_MixedWithMovedSplitMerged(t *testing.T) {
	reqs := []RequirementDiff{
		makeReq("SV-001", StateFixed),
		makeReq("SV-002", StateMoved),
		makeReq("SV-003", StateSplit),
		makeReq("SV-004", StateMerged),
		makeReq("SV-005", StateNew),
	}
	got := ComputeSummary(reqs)

	if got.Total != 5 {
		t.Errorf("Total: got %d, want 5", got.Total)
	}
	if got.Fixed != 1 {
		t.Errorf("Fixed: got %d, want 1", got.Fixed)
	}
	if got.New != 1 {
		t.Errorf("New: got %d, want 1", got.New)
	}
	// Expect 4 matched: fixed, moved, split, merged.
	if got.MatchedCount != 4 {
		t.Errorf("MatchedCount: got %d, want 4", got.MatchedCount)
	}
	if got.UnmatchedNewCount != 1 {
		t.Errorf("UnmatchedNewCount: got %d, want 1", got.UnmatchedNewCount)
	}
}
