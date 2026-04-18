package diff

// nginx_integration_test.go replicates the 11 tests from
// hdf-diff/test/nginx-diff.test.ts using the shared v1 InSpec fixtures.
//
// Fixture direction: nginx-failing (before) -> nginx-clean (after).
// All 41 controls should match; 3 are fixed, 0 regressed.

import (
	"testing"
)

var nginx v1FixturePair

func ensureNginxFixtures(t *testing.T) {
	t.Helper()
	loadV1FixturePair(t, &nginx, "nginx-failing.json", "nginx-clean.json")
}

// TestNginx_V1FormatDetection verifies both fixtures are detected as v1 format.
func TestNginx_V1FormatDetection(t *testing.T) {
	ensureNginxFixtures(t)

	if !IsV1Format(nginx.beforeRaw) {
		t.Error("nginx-failing.json should be detected as v1 format")
	}
	if !IsV1Format(nginx.afterRaw) {
		t.Error("nginx-clean.json should be detected as v1 format")
	}
}

// TestNginx_NonEmptyDiff verifies the diff produces non-empty results.
func TestNginx_NonEmptyDiff(t *testing.T) {
	ensureNginxFixtures(t)

	if len(nginx.diff.RequirementDiffs) == 0 {
		t.Error("requirementDiffs should not be empty")
	}
	if nginx.diff.Summary.Total == 0 {
		t.Error("summary.total should be greater than 0")
	}
}

// TestNginx_FixedRequirements verifies fixed requirements are detected (failing -> clean).
func TestNginx_FixedRequirements(t *testing.T) {
	ensureNginxFixtures(t)

	if nginx.diff.Summary.Fixed == 0 {
		t.Error("summary.fixed should be greater than 0")
	}
}

// TestNginx_BaselinesMatchedByProfileName verifies baselines are matched by profile name.
func TestNginx_BaselinesMatchedByProfileName(t *testing.T) {
	ensureNginxFixtures(t)

	if len(nginx.diff.BaselineDiffs) == 0 {
		t.Fatal("baselineDiffs should not be empty")
	}
	baseline := nginx.diff.BaselineDiffs[0]
	if baseline.Name == "" {
		t.Error("baseline name should not be empty")
	}
}

// TestNginx_RequirementsMatchedByControlID verifies all controls match with no new or absent.
func TestNginx_RequirementsMatchedByControlID(t *testing.T) {
	ensureNginxFixtures(t)

	for _, req := range nginx.diff.RequirementDiffs {
		if req.State == StateNew || req.State == StateAbsent {
			t.Errorf("requirement %s has unexpected state %q -- same baseline should have no new or absent", req.ID, req.State)
		}
	}
}

// TestNginx_TotalControls verifies the total is 41 controls.
func TestNginx_TotalControls(t *testing.T) {
	ensureNginxFixtures(t)

	if nginx.diff.Summary.Total != 41 {
		t.Errorf("summary.total = %d, want 41", nginx.diff.Summary.Total)
	}
}

// TestNginx_SumEqualsTotal verifies fixed + regressed + unchanged + updated + new + absent = total.
func TestNginx_SumEqualsTotal(t *testing.T) {
	ensureNginxFixtures(t)

	s := nginx.diff.Summary
	sum := s.Fixed + s.Regressed + s.Unchanged + s.Updated + s.New + s.Absent
	if sum != s.Total {
		t.Errorf("sum of states (%d) != total (%d): fixed=%d regressed=%d unchanged=%d updated=%d new=%d absent=%d",
			sum, s.Total, s.Fixed, s.Regressed, s.Unchanged, s.Updated, s.New, s.Absent)
	}
}

// TestNginx_NoRegressions verifies no regressions occur when diffing failing -> clean.
func TestNginx_NoRegressions(t *testing.T) {
	ensureNginxFixtures(t)

	if nginx.diff.Summary.Regressed != 0 {
		t.Errorf("summary.regressed = %d, want 0 (failing -> clean should produce no regressions)", nginx.diff.Summary.Regressed)
	}
}

// TestNginx_FixedHaveResultChanged verifies changeReasons includes resultChanged for fixed requirements.
func TestNginx_FixedHaveResultChanged(t *testing.T) {
	ensureNginxFixtures(t)

	fixedReqs := filterByState(nginx.diff.RequirementDiffs, StateFixed)
	if len(fixedReqs) == 0 {
		t.Fatal("expected at least one fixed requirement")
	}
	for _, req := range fixedReqs {
		if !containsReason(req.ChangeReasons, ReasonResultChanged) {
			t.Errorf("fixed requirement %s missing resultChanged in changeReasons: %v", req.ID, req.ChangeReasons)
		}
	}
}

// TestNginx_FormatVersionAndComparisonMode verifies formatVersion and comparisonMode are set.
func TestNginx_FormatVersionAndComparisonMode(t *testing.T) {
	ensureNginxFixtures(t)

	if nginx.diff.FormatVersion != "1.0.0" {
		t.Errorf("formatVersion = %q, want %q", nginx.diff.FormatVersion, "1.0.0")
	}
	if nginx.diff.ComparisonMode != ModeTemporal {
		t.Errorf("comparisonMode = %q, want %q", nginx.diff.ComparisonMode, ModeTemporal)
	}
}

// TestNginx_MatchedHaveBeforeAfter verifies all matched requirements have before/after snapshots.
func TestNginx_MatchedHaveBeforeAfter(t *testing.T) {
	ensureNginxFixtures(t)

	matched := 0
	for _, req := range nginx.diff.RequirementDiffs {
		if req.State == StateNew || req.State == StateAbsent {
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
