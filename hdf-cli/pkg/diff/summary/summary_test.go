package summary

import (
	"testing"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
)

// makeReq builds a minimal RequirementDiff with only the fields ComputeSummary needs.
func makeReq(id string, state types.RequirementState) types.RequirementDiff {
	return types.RequirementDiff{
		ID:            id,
		State:         state,
		ChangeReasons: []types.ChangeReason{},
		FieldChanges:  []types.FieldChange{},
	}
}

func TestComputeSummary(t *testing.T) {
	tests := []struct {
		name     string
		reqs     []types.RequirementDiff
		expected types.ComparisonSummary
	}{
		{
			name: "empty array returns all zeros",
			reqs: []types.RequirementDiff{},
			expected: types.ComparisonSummary{
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
			reqs: []types.RequirementDiff{
				makeReq("SV-001", types.StateFixed),
				makeReq("SV-002", types.StateFixed),
				makeReq("SV-003", types.StateFixed),
			},
			expected: types.ComparisonSummary{
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
			reqs: []types.RequirementDiff{
				makeReq("SV-001", types.StateRegressed),
				makeReq("SV-002", types.StateRegressed),
				makeReq("SV-003", types.StateRegressed),
				makeReq("SV-004", types.StateRegressed),
			},
			expected: types.ComparisonSummary{
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
			reqs: []types.RequirementDiff{
				makeReq("SV-001", types.StateFixed),
				makeReq("SV-002", types.StateFixed),
				makeReq("SV-003", types.StateRegressed),
				makeReq("SV-004", types.StateUnchanged),
				makeReq("SV-005", types.StateUnchanged),
				makeReq("SV-006", types.StateUnchanged),
				makeReq("SV-007", types.StateNew),
				makeReq("SV-008", types.StateAbsent),
				makeReq("SV-009", types.StateUpdated),
			},
			expected: types.ComparisonSummary{
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
			reqs: []types.RequirementDiff{
				makeReq("SV-001", types.StateUnchanged),
			},
			expected: types.ComparisonSummary{
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
			reqs: []types.RequirementDiff{
				makeReq("SV-001", types.StateNew),
				makeReq("SV-002", types.StateNew),
				makeReq("SV-003", types.StateNew),
				makeReq("SV-004", types.StateNew),
				makeReq("SV-005", types.StateNew),
			},
			expected: types.ComparisonSummary{
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
