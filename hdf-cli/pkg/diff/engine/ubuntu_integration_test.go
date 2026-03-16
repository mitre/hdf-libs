package engine

// ubuntu_integration_test.go replicates the 10 tests from
// hdf-diff/test/ubuntu-diff.test.ts using the shared v1 OHDF fixtures.
//
// Fixture direction: ubuntu-22-vanilla (before) -> ubuntu-22-hardened (after).
// All 192 controls should match; hardening fixes most failures but introduces
// 2 regressions (SV-260500, SV-260601).

import (
	"testing"

	"github.com/mitre/hdf-cli/pkg/diff/normalize"
	types "github.com/mitre/hdf-cli/pkg/diff/types"
)

var ubuntu v1FixturePair

func ensureUbuntuFixtures(t *testing.T) {
	t.Helper()
	loadV1FixturePair(t, &ubuntu, "ubuntu-22-vanilla.json", "ubuntu-22-hardened.json")
}

// TestUbuntu_V1FormatDetection verifies both fixtures are detected as v1 format.
func TestUbuntu_V1FormatDetection(t *testing.T) {
	ensureUbuntuFixtures(t)

	if !normalize.IsV1Format(ubuntu.beforeRaw) {
		t.Error("ubuntu-22-vanilla.json should be detected as v1 format")
	}
	if !normalize.IsV1Format(ubuntu.afterRaw) {
		t.Error("ubuntu-22-hardened.json should be detected as v1 format")
	}
}

// TestUbuntu_NonEmptyDiff verifies the diff produces non-empty results.
func TestUbuntu_NonEmptyDiff(t *testing.T) {
	ensureUbuntuFixtures(t)

	if len(ubuntu.diff.RequirementDiffs) == 0 {
		t.Error("requirementDiffs should not be empty")
	}
	if ubuntu.diff.Summary.Total == 0 {
		t.Error("summary.total should be greater than 0")
	}
}

// TestUbuntu_TotalControls verifies total = 192 (same controls in both scans).
func TestUbuntu_TotalControls(t *testing.T) {
	ensureUbuntuFixtures(t)

	if ubuntu.diff.Summary.Total != 192 {
		t.Errorf("summary.total = %d, want 192", ubuntu.diff.Summary.Total)
	}
}

// TestUbuntu_FixedRequirements verifies fixed requirements are detected (vanilla -> hardened).
func TestUbuntu_FixedRequirements(t *testing.T) {
	ensureUbuntuFixtures(t)

	if ubuntu.diff.Summary.Fixed == 0 {
		t.Error("summary.fixed should be greater than 0")
	}
}

// TestUbuntu_NoNewOrAbsent verifies no added or removed requirements (same baseline).
func TestUbuntu_NoNewOrAbsent(t *testing.T) {
	ensureUbuntuFixtures(t)

	if ubuntu.diff.Summary.New != 0 {
		t.Errorf("summary.new = %d, want 0", ubuntu.diff.Summary.New)
	}
	if ubuntu.diff.Summary.Absent != 0 {
		t.Errorf("summary.absent = %d, want 0", ubuntu.diff.Summary.Absent)
	}
}

// TestUbuntu_SumEqualsTotal verifies fixed + regressed + unchanged + updated + new + absent = total.
func TestUbuntu_SumEqualsTotal(t *testing.T) {
	ensureUbuntuFixtures(t)

	s := ubuntu.diff.Summary
	sum := s.Fixed + s.Regressed + s.Unchanged + s.Updated + s.New + s.Absent
	if sum != s.Total {
		t.Errorf("sum of states (%d) != total (%d): fixed=%d regressed=%d unchanged=%d updated=%d new=%d absent=%d",
			sum, s.Total, s.Fixed, s.Regressed, s.Unchanged, s.Updated, s.New, s.Absent)
	}
}

// TestUbuntu_Regressions verifies exactly 2 regressions: SV-260500 and SV-260601.
func TestUbuntu_Regressions(t *testing.T) {
	ensureUbuntuFixtures(t)

	if ubuntu.diff.Summary.Regressed != 2 {
		t.Errorf("summary.regressed = %d, want 2", ubuntu.diff.Summary.Regressed)
	}

	regressedIDs := make(map[string]bool)
	for _, req := range ubuntu.diff.RequirementDiffs {
		if req.State == types.StateRegressed {
			regressedIDs[req.ID] = true
		}
	}
	expectedIDs := []string{"SV-260500", "SV-260601"}
	for _, id := range expectedIDs {
		if !regressedIDs[id] {
			t.Errorf("expected %s to be regressed, but it was not found in regressed set: %v", id, regressedIDs)
		}
	}
}

// TestUbuntu_MatchedHaveBeforeAfter verifies all matched requirements have before/after snapshots.
func TestUbuntu_MatchedHaveBeforeAfter(t *testing.T) {
	ensureUbuntuFixtures(t)

	matched := 0
	for _, req := range ubuntu.diff.RequirementDiffs {
		if req.State == types.StateNew || req.State == types.StateAbsent {
			continue
		}
		matched++
		if req.Before == nil {
			t.Errorf("requirement %s: before should not be nil", req.ID)
		}
		if req.After == nil {
			t.Errorf("requirement %s: after should not be nil", req.ID)
		}
	}
	if matched == 0 {
		t.Error("expected at least one matched requirement")
	}
}

// TestUbuntu_FormatVersionAndComparisonMode verifies formatVersion and comparisonMode are correct.
func TestUbuntu_FormatVersionAndComparisonMode(t *testing.T) {
	ensureUbuntuFixtures(t)

	if ubuntu.diff.FormatVersion != "1.0.0" {
		t.Errorf("formatVersion = %q, want %q", ubuntu.diff.FormatVersion, "1.0.0")
	}
	if ubuntu.diff.ComparisonMode != types.ModeTemporal {
		t.Errorf("comparisonMode = %q, want %q", ubuntu.diff.ComparisonMode, types.ModeTemporal)
	}
}

// TestUbuntu_FixedHaveResultChanged verifies changeReasons includes resultChanged for fixed requirements.
func TestUbuntu_FixedHaveResultChanged(t *testing.T) {
	ensureUbuntuFixtures(t)

	fixedReqs := filterByState(ubuntu.diff.RequirementDiffs, types.StateFixed)
	if len(fixedReqs) == 0 {
		t.Fatal("expected at least one fixed requirement")
	}
	for _, req := range fixedReqs {
		if !containsReason(req.ChangeReasons, types.ReasonResultChanged) {
			t.Errorf("fixed requirement %s missing resultChanged in changeReasons: %v", req.ID, req.ChangeReasons)
		}
	}
}
