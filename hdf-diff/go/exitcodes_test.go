package diff

import (
	"testing"
)

// makeSummary builds a ComparisonSummary with sensible defaults (all unchanged).
// Override individual fields as needed for each test scenario.
func makeSummary(overrides ...func(*ComparisonSummary)) ComparisonSummary {
	s := ComparisonSummary{
		Total:             10,
		Fixed:             0,
		Regressed:         0,
		New:               0,
		Absent:            0,
		Unchanged:         10,
		Updated:           0,
		MatchedCount:      10,
		UnmatchedOldCount: 0,
		UnmatchedNewCount: 0,
	}
	for _, o := range overrides {
		o(&s)
	}
	return s
}

// ── Constants ───────────────────────────────────────────────────────────

func TestConstants_BasicExitCodes(t *testing.T) {
	t.Run("GNU diff compatible constants have correct values", func(t *testing.T) {
		if Identical != 0 {
			t.Errorf("Identical = %d, want 0", Identical)
		}
		if Differences != 1 {
			t.Errorf("Differences = %d, want 1", Differences)
		}
		if Error != 2 {
			t.Errorf("Error = %d, want 2", Error)
		}
	})
}

func TestConstants_DetailedExitCodes(t *testing.T) {
	t.Run("detailed exit code constants have correct values", func(t *testing.T) {
		if FixesOnly != 10 {
			t.Errorf("FixesOnly = %d, want 10", FixesOnly)
		}
		if RegressionsOnly != 11 {
			t.Errorf("RegressionsOnly = %d, want 11", RegressionsOnly)
		}
		if Mixed != 12 {
			t.Errorf("Mixed = %d, want 12", Mixed)
		}
		if BaselineChanged != 13 {
			t.Errorf("BaselineChanged = %d, want 13", BaselineChanged)
		}
		if DriftOnly != 14 {
			t.Errorf("DriftOnly = %d, want 14", DriftOnly)
		}
	})
}

// ── ComputeBasicExitCode ────────────────────────────────────────────────

func TestComputeBasicExitCode(t *testing.T) {
	tests := []struct {
		name     string
		summary  ComparisonSummary
		expected int
	}{
		{
			name:     "all unchanged returns 0 (identical)",
			summary:  makeSummary(),
			expected: 0,
		},
		{
			name: "some fixed returns 1",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Fixed = 3
				s.Unchanged = 7
			}),
			expected: 1,
		},
		{
			name: "some regressed returns 1",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Regressed = 2
				s.Unchanged = 8
			}),
			expected: 1,
		},
		{
			name: "mixed fixes and regressions returns 1",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Fixed = 2
				s.Regressed = 1
				s.Unchanged = 7
			}),
			expected: 1,
		},
		{
			name: "only new controls returns 1",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.New = 2
				s.Unchanged = 10
				s.Total = 12
				s.UnmatchedNewCount = 2
				s.MatchedCount = 10
			}),
			expected: 1,
		},
		{
			name: "only absent controls returns 1",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Absent = 3
				s.Unchanged = 7
				s.Total = 10
				s.UnmatchedOldCount = 3
				s.MatchedCount = 7
			}),
			expected: 1,
		},
		{
			name: "only metadata drift (updated) returns 1",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Updated = 1
				s.Unchanged = 9
			}),
			expected: 1,
		},
		{
			name: "empty comparison (total=0) returns 0",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Total = 0
				s.Unchanged = 0
				s.MatchedCount = 0
			}),
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeBasicExitCode(tc.summary)
			if got != tc.expected {
				t.Errorf("ComputeBasicExitCode() = %d, want %d", got, tc.expected)
			}
		})
	}
}

// ── ComputeDetailedExitCode ─────────────────────────────────────────────

func TestComputeDetailedExitCode(t *testing.T) {
	tests := []struct {
		name     string
		summary  ComparisonSummary
		expected int
	}{
		{
			name:     "all unchanged returns 0 (identical)",
			summary:  makeSummary(),
			expected: 0,
		},
		{
			name: "fixes only returns 10",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Fixed = 3
				s.Unchanged = 7
			}),
			expected: 10,
		},
		{
			name: "regressions only returns 11",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Regressed = 2
				s.Unchanged = 8
			}),
			expected: 11,
		},
		{
			name: "mixed fixes and regressions returns 12",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Fixed = 2
				s.Regressed = 1
				s.Unchanged = 7
			}),
			expected: 12,
		},
		{
			name: "only new controls returns 13",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.New = 2
				s.Unchanged = 10
				s.Total = 12
				s.UnmatchedNewCount = 2
				s.MatchedCount = 10
			}),
			expected: 13,
		},
		{
			name: "only absent controls returns 13",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Absent = 3
				s.Unchanged = 7
				s.Total = 10
				s.UnmatchedOldCount = 3
				s.MatchedCount = 7
			}),
			expected: 13,
		},
		{
			name: "new and absent but no status changes returns 13",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.New = 1
				s.Absent = 1
				s.Unchanged = 8
				s.Total = 10
				s.UnmatchedNewCount = 1
				s.UnmatchedOldCount = 1
				s.MatchedCount = 8
			}),
			expected: 13,
		},
		{
			name: "only metadata drift (updated) returns 14",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Updated = 1
				s.Unchanged = 9
			}),
			expected: 14,
		},
		{
			name: "fixes and new controls returns 10 (fixes priority over baseline)",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Fixed = 2
				s.New = 1
				s.Unchanged = 7
				s.Total = 10
				s.UnmatchedNewCount = 1
				s.MatchedCount = 9
			}),
			expected: 10,
		},
		{
			name: "regressions and absent controls returns 11 (regressions priority)",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Regressed = 1
				s.Absent = 2
				s.Unchanged = 7
				s.Total = 10
				s.UnmatchedOldCount = 2
				s.MatchedCount = 8
			}),
			expected: 11,
		},
		{
			name: "fixes regressions new absent all present returns 12 (mixed priority)",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Fixed = 1
				s.Regressed = 1
				s.New = 1
				s.Absent = 1
				s.Unchanged = 6
				s.Total = 10
				s.UnmatchedNewCount = 1
				s.UnmatchedOldCount = 1
				s.MatchedCount = 8
			}),
			expected: 12,
		},
		{
			name: "updated and new returns 13 (baseline priority over drift)",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Updated = 1
				s.New = 1
				s.Unchanged = 8
				s.Total = 10
				s.UnmatchedNewCount = 1
				s.MatchedCount = 9
			}),
			expected: 13,
		},
		{
			name: "empty comparison (total=0) returns 0",
			summary: makeSummary(func(s *ComparisonSummary) {
				s.Total = 0
				s.Unchanged = 0
				s.MatchedCount = 0
			}),
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeDetailedExitCode(tc.summary)
			if got != tc.expected {
				t.Errorf("ComputeDetailedExitCode() = %d, want %d", got, tc.expected)
			}
		})
	}
}
