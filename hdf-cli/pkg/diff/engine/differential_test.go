package engine

// Differential tests verify that the Go diff engine produces the same output as
// the TypeScript hdf-diff library for shared fixture files. The TypeScript tests
// are the reference implementation — if both produce identical summary counts,
// requirement states, and change reasons for the same inputs, they are equivalent.
//
// Reference values were captured by running the TypeScript diffHdf() on each
// fixture pair and recording the output (summary counts, per-requirement states,
// changeReasons, etc.).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mitre/hdf-cli/pkg/diff/normalize"
	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// fixturesDir returns the absolute path to the shared test fixtures directory.
// The fixtures live in hdf-diff/test/fixtures/ (sibling monorepo package).
func fixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// From hdf-cli/pkg/diff/engine/ up to hdf-libs root, then into hdf-diff/test/fixtures
	dir := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "hdf-diff", "test", "fixtures")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("filepath.Abs failed: %v", err)
	}
	return absDir
}

// loadV2Fixture loads a v2-format HDF JSON fixture into hdf.HdfResults.
func loadV2Fixture(t *testing.T, name string) hdf.HdfResults {
	t.Helper()
	path := filepath.Join(fixturesDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s not found: %v (run from monorepo root)", name, err)
	}
	result, err := hdf.UnmarshalHdfResults(data)
	if err != nil {
		t.Fatalf("failed to parse v2 fixture %s: %v", name, err)
	}
	return result
}

// loadV1Fixture loads a v1-format InSpec exec-json fixture, normalizes it to v2,
// and returns hdf.HdfResults.
func loadV1Fixture(t *testing.T, name string) hdf.HdfResults {
	t.Helper()
	path := filepath.Join(fixturesDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s not found: %v (run from monorepo root)", name, err)
	}

	// Verify v1 format detection
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse JSON for %s: %v", name, err)
	}
	if !normalize.IsV1Format(raw) {
		t.Fatalf("expected %s to be v1 format", name)
	}

	result, warnings, err := normalize.ToV2(data)
	if err != nil {
		t.Fatalf("failed to normalize v1 fixture %s: %v", name, err)
	}
	if len(warnings) > 0 {
		t.Logf("normalization warnings for %s: %v", name, warnings)
	}
	return result
}

// Helper functions findReq and containsReason are defined in engine_test.go
// and drift_test.go respectively. We reuse them here.

// ---------------------------------------------------------------------------
// Test 1: V2 scan-before vs scan-after
// ---------------------------------------------------------------------------
// TS reference: fixed=1, regressed=1, new=1, absent=1, unchanged=1, updated=1
//               total=6, matchedCount=4, unmatchedOldCount=1, unmatchedNewCount=1
//
// Per-requirement:
//   SV-001: state=fixed,     old=failed,  new=passed
//   SV-002: state=unchanged, old=passed,  new=passed
//   SV-003: state=regressed, old=passed,  new=failed
//   SV-004: state=absent,    old=failed
//   SV-005: state=updated,   impactChanged, oldImpact=0.3, newImpact=0.0
//   SV-006: state=new,                      new=passed

func TestDifferential_V2_BeforeAfter(t *testing.T) {
	oldDoc := loadV2Fixture(t, "scan-before.json")
	newDoc := loadV2Fixture(t, "scan-after.json")

	diff, err := DiffHdf(oldDoc, []hdf.HdfResults{newDoc}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	// ── Top-level structure ──────────────────────────────────────────────
	t.Run("formatVersion", func(t *testing.T) {
		if diff.FormatVersion != version100 {
			t.Errorf("formatVersion = %q, want %q", diff.FormatVersion, version100)
		}
	})

	t.Run("comparisonMode", func(t *testing.T) {
		if diff.ComparisonMode != types.ModeTemporal {
			t.Errorf("comparisonMode = %q, want %q", diff.ComparisonMode, types.ModeTemporal)
		}
	})

	t.Run("sources", func(t *testing.T) {
		if len(diff.Sources) != 2 {
			t.Fatalf("sources length = %d, want 2", len(diff.Sources))
		}
		if diff.Sources[0].Role != types.RoleOld {
			t.Errorf("sources[0].role = %q, want %q", diff.Sources[0].Role, types.RoleOld)
		}
		if diff.Sources[1].Role != types.RoleNew {
			t.Errorf("sources[1].role = %q, want %q", diff.Sources[1].Role, types.RoleNew)
		}
	})

	t.Run("matching", func(t *testing.T) {
		if diff.Matching == nil {
			t.Fatal("matching is nil")
		}
		if diff.Matching.PrimaryStrategy != stratExactID {
			t.Errorf("matching.primaryStrategy = %q, want %q", diff.Matching.PrimaryStrategy, stratExactID)
		}
	})

	// ── Summary counts ───────────────────────────────────────────────────
	t.Run("summary", func(t *testing.T) {
		s := diff.Summary
		assertSummary(t, s, 1, 1, 1, 1, 1, 1, 6, 4, 1, 1)
	})

	// ── Per-requirement assertions ───────────────────────────────────────
	t.Run("SV-001_fixed", func(t *testing.T) {
		req := findReq(diff.RequirementDiffs, "SV-001")
		if req == nil {
			t.Fatal("SV-001 not found")
		}
		assertState(t, req, types.StateFixed)
		assertStatuses(t, req, "failed", "passed")
		if !containsReason(req.ChangeReasons, types.ReasonResultChanged) {
			t.Error("expected resultChanged in changeReasons")
		}
		if req.MatchStrategy != stratExactID {
			t.Errorf("matchStrategy = %q, want %q", req.MatchStrategy, stratExactID)
		}
		if req.MatchConfidence == nil || *req.MatchConfidence != 1.0 {
			t.Error("matchConfidence should be 1.0")
		}
		if req.Before == nil {
			t.Error("before should not be nil")
		}
		if req.After == nil {
			t.Error("after should not be nil")
		}
	})

	t.Run("SV-002_unchanged", func(t *testing.T) {
		req := findReq(diff.RequirementDiffs, "SV-002")
		if req == nil {
			t.Fatal("SV-002 not found")
		}
		assertState(t, req, types.StateUnchanged)
		assertStatuses(t, req, "passed", "passed")
		if len(req.FieldChanges) != 0 {
			t.Errorf("fieldChanges should be empty, got %d", len(req.FieldChanges))
		}
		if len(req.ChangeReasons) != 0 {
			t.Errorf("changeReasons should be empty, got %v", req.ChangeReasons)
		}
	})

	t.Run("SV-003_regressed", func(t *testing.T) {
		req := findReq(diff.RequirementDiffs, "SV-003")
		if req == nil {
			t.Fatal("SV-003 not found")
		}
		assertState(t, req, types.StateRegressed)
		assertStatuses(t, req, "passed", "failed")
		if !containsReason(req.ChangeReasons, types.ReasonResultChanged) {
			t.Error("expected resultChanged in changeReasons")
		}
	})

	t.Run("SV-004_absent", func(t *testing.T) {
		req := findReq(diff.RequirementDiffs, "SV-004")
		if req == nil {
			t.Fatal("SV-004 not found")
		}
		assertState(t, req, types.StateAbsent)
		if req.OldEffectiveStatus != "failed" {
			t.Errorf("oldEffectiveStatus = %q, want %q", req.OldEffectiveStatus, "failed")
		}
		if req.NewEffectiveStatus != "" {
			t.Errorf("newEffectiveStatus = %q, want empty", req.NewEffectiveStatus)
		}
		if req.Title != "Ensure FIPS mode is enabled" {
			t.Errorf("title = %q, want %q", req.Title, "Ensure FIPS mode is enabled")
		}
		if req.Before == nil {
			t.Error("before should not be nil for absent requirement")
		}
		if req.After != nil {
			t.Error("after should be nil for absent requirement")
		}
	})

	t.Run("SV-005_updated_impactChanged", func(t *testing.T) {
		req := findReq(diff.RequirementDiffs, "SV-005")
		if req == nil {
			t.Fatal("SV-005 not found")
		}
		assertState(t, req, types.StateUpdated)
		if !containsReason(req.ChangeReasons, types.ReasonImpactChanged) {
			t.Error("expected impactChanged in changeReasons")
		}
		if req.OldImpact == nil || *req.OldImpact != 0.3 {
			t.Errorf("oldImpact = %v, want 0.3", req.OldImpact)
		}
		if req.NewImpact == nil || *req.NewImpact != 0.0 {
			t.Errorf("newImpact = %v, want 0.0", req.NewImpact)
		}
		// Field changes should include impact replace
		foundImpactChange := false
		for _, fc := range req.FieldChanges {
			if fc.Path == "impact" && fc.Op == types.OpReplace {
				foundImpactChange = true
				if fc.OldValue != 0.3 {
					t.Errorf("fieldChange impact oldValue = %v, want 0.3", fc.OldValue)
				}
				if fc.NewValue != 0.0 {
					t.Errorf("fieldChange impact newValue = %v, want 0.0", fc.NewValue)
				}
			}
		}
		if !foundImpactChange {
			t.Error("expected impact replace in fieldChanges")
		}
	})

	t.Run("SV-006_new", func(t *testing.T) {
		req := findReq(diff.RequirementDiffs, "SV-006")
		if req == nil {
			t.Fatal("SV-006 not found")
		}
		assertState(t, req, types.StateNew)
		if req.OldEffectiveStatus != "" {
			t.Errorf("oldEffectiveStatus = %q, want empty", req.OldEffectiveStatus)
		}
		if req.NewEffectiveStatus != "passed" {
			t.Errorf("newEffectiveStatus = %q, want %q", req.NewEffectiveStatus, "passed")
		}
		if req.Title != "Ensure SELinux is enforcing" {
			t.Errorf("title = %q, want %q", req.Title, "Ensure SELinux is enforcing")
		}
		if req.Before != nil {
			t.Error("before should be nil for new requirement")
		}
		if req.After == nil {
			t.Error("after should not be nil for new requirement")
		}
	})

	// ── Baseline diffs ───────────────────────────────────────────────────
	t.Run("baselineDiffs", func(t *testing.T) {
		if len(diff.BaselineDiffs) != 1 {
			t.Fatalf("baselineDiffs length = %d, want 1", len(diff.BaselineDiffs))
		}
		bd := diff.BaselineDiffs[0]
		if bd.Name != "rhel9-stig-baseline" {
			t.Errorf("baseline name = %q, want %q", bd.Name, "rhel9-stig-baseline")
		}
		if bd.OldVersion != version100 {
			t.Errorf("oldVersion = %q, want %q", bd.OldVersion, version100)
		}
		if bd.NewVersion != "1.1.0" {
			t.Errorf("newVersion = %q, want %q", bd.NewVersion, "1.1.0")
		}
		if bd.State != types.StateUpdated {
			t.Errorf("state = %q, want %q", bd.State, types.StateUpdated)
		}
	})

	// ── Requirement ordering (sorted by ID) ──────────────────────────────
	t.Run("sorted_by_id", func(t *testing.T) {
		for i := 1; i < len(diff.RequirementDiffs); i++ {
			prev := diff.RequirementDiffs[i-1].ID
			curr := diff.RequirementDiffs[i].ID
			if prev > curr {
				t.Errorf("requirementDiffs not sorted: %q > %q at index %d", prev, curr, i)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Test 2: V2 identical documents
// ---------------------------------------------------------------------------
// TS reference: fixed=0, regressed=0, new=0, absent=0, unchanged=5, updated=0
//               total=5, matchedCount=5, unmatchedOldCount=0, unmatchedNewCount=0

func TestDifferential_V2_Identical(t *testing.T) {
	doc := loadV2Fixture(t, "scan-before.json")

	diff, err := DiffHdf(doc, []hdf.HdfResults{doc}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	t.Run("summary", func(t *testing.T) {
		assertSummary(t, diff.Summary, 0, 0, 0, 0, 5, 0, 5, 5, 0, 0)
	})

	t.Run("all_unchanged", func(t *testing.T) {
		for _, req := range diff.RequirementDiffs {
			if req.State != types.StateUnchanged {
				t.Errorf("requirement %s state = %q, want %q", req.ID, req.State, types.StateUnchanged)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Test 3: V2 scan-before vs scan-with-override
// ---------------------------------------------------------------------------
// TS reference: fixed=1, regressed=0, new=0, absent=4, unchanged=0, updated=0
//               total=5, matchedCount=1, unmatchedOldCount=4, unmatchedNewCount=0
//
// SV-001: state=fixed, old=failed, new=passed, reasons=[overrideAdded]
// SV-002..SV-005: state=absent (only SV-001 exists in override doc)

func TestDifferential_V2_WithOverride(t *testing.T) {
	oldDoc := loadV2Fixture(t, "scan-before.json")
	newDoc := loadV2Fixture(t, "scan-with-override.json")

	diff, err := DiffHdf(oldDoc, []hdf.HdfResults{newDoc}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	t.Run("summary", func(t *testing.T) {
		assertSummary(t, diff.Summary, 1, 0, 0, 4, 0, 0, 5, 1, 4, 0)
	})

	t.Run("SV-001_overrideAdded", func(t *testing.T) {
		req := findReq(diff.RequirementDiffs, "SV-001")
		if req == nil {
			t.Fatal("SV-001 not found")
		}
		assertState(t, req, types.StateFixed)
		assertStatuses(t, req, "failed", "passed")
		if !containsReason(req.ChangeReasons, types.ReasonOverrideAdded) {
			t.Errorf("expected overrideAdded in changeReasons, got %v", req.ChangeReasons)
		}
	})

	t.Run("absent_requirements", func(t *testing.T) {
		for _, id := range []string{"SV-002", "SV-003", "SV-004", "SV-005"} {
			req := findReq(diff.RequirementDiffs, id)
			if req == nil {
				t.Errorf("%s not found", id)
				continue
			}
			if req.State != types.StateAbsent {
				t.Errorf("%s state = %q, want %q", id, req.State, types.StateAbsent)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Test 4: V1 nginx fixtures (failing -> clean)
// ---------------------------------------------------------------------------
// TS reference: fixed=3, regressed=0, new=0, absent=0, unchanged=38, updated=0
//               total=41, matchedCount=41, unmatchedOldCount=0, unmatchedNewCount=0

func TestDifferential_V1_Nginx(t *testing.T) {
	nginxFailing := loadV1Fixture(t, "nginx-failing.json")
	nginxClean := loadV1Fixture(t, "nginx-clean.json")

	diff, err := DiffHdf(nginxFailing, []hdf.HdfResults{nginxClean}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	t.Run("total", func(t *testing.T) {
		if diff.Summary.Total != 41 {
			t.Errorf("total = %d, want 41", diff.Summary.Total)
		}
	})

	t.Run("summary", func(t *testing.T) {
		assertSummary(t, diff.Summary, 3, 0, 0, 0, 38, 0, 41, 41, 0, 0)
	})

	t.Run("no_new_or_absent", func(t *testing.T) {
		for _, req := range diff.RequirementDiffs {
			if req.State == types.StateNew || req.State == types.StateAbsent {
				t.Errorf("requirement %s has unexpected state %q", req.ID, req.State)
			}
		}
	})

	t.Run("no_regressions", func(t *testing.T) {
		if diff.Summary.Regressed != 0 {
			t.Errorf("regressed = %d, want 0", diff.Summary.Regressed)
		}
	})

	t.Run("fixed_have_resultChanged", func(t *testing.T) {
		fixedReqs := filterByState(diff.RequirementDiffs, types.StateFixed)
		if len(fixedReqs) == 0 {
			t.Fatal("expected at least one fixed requirement")
		}
		for _, req := range fixedReqs {
			if !containsReason(req.ChangeReasons, types.ReasonResultChanged) {
				t.Errorf("fixed requirement %s missing resultChanged in changeReasons", req.ID)
			}
		}
	})

	t.Run("matched_have_before_after", func(t *testing.T) {
		for _, req := range diff.RequirementDiffs {
			if req.State == types.StateNew || req.State == types.StateAbsent {
				continue
			}
			if req.Before == nil {
				t.Errorf("requirement %s before is nil", req.ID)
			}
			if req.After == nil {
				t.Errorf("requirement %s after is nil", req.ID)
			}
		}
	})

	t.Run("formatVersion_and_mode", func(t *testing.T) {
		if diff.FormatVersion != version100 {
			t.Errorf("formatVersion = %q, want %q", diff.FormatVersion, version100)
		}
		if diff.ComparisonMode != types.ModeTemporal {
			t.Errorf("comparisonMode = %q, want %q", diff.ComparisonMode, types.ModeTemporal)
		}
	})

	t.Run("sum_equals_total", func(t *testing.T) {
		s := diff.Summary
		sum := s.Fixed + s.Regressed + s.New + s.Absent + s.Unchanged + s.Updated
		if sum != s.Total {
			t.Errorf("sum of states (%d) != total (%d)", sum, s.Total)
		}
	})

	t.Run("baseline_matched", func(t *testing.T) {
		if len(diff.BaselineDiffs) == 0 {
			t.Error("expected at least one baseline diff")
		} else if diff.BaselineDiffs[0].Name == "" {
			t.Error("baseline name should not be empty")
		}
	})
}

// ---------------------------------------------------------------------------
// Test 5: V1 Ubuntu fixtures (vanilla -> hardened)
// ---------------------------------------------------------------------------
// TS reference: fixed=95, regressed=2, new=0, absent=0, unchanged=95, updated=0
//               total=192, matchedCount=192, unmatchedOldCount=0, unmatchedNewCount=0
//               Regressed IDs: SV-260500, SV-260601

func TestDifferential_V1_Ubuntu(t *testing.T) {
	vanilla := loadV1Fixture(t, "ubuntu-22-vanilla.json")
	hardened := loadV1Fixture(t, "ubuntu-22-hardened.json")

	diff, err := DiffHdf(vanilla, []hdf.HdfResults{hardened}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	t.Run("total", func(t *testing.T) {
		if diff.Summary.Total != 192 {
			t.Errorf("total = %d, want 192", diff.Summary.Total)
		}
	})

	t.Run("summary", func(t *testing.T) {
		assertSummary(t, diff.Summary, 95, 2, 0, 0, 95, 0, 192, 192, 0, 0)
	})

	t.Run("no_new_or_absent", func(t *testing.T) {
		if diff.Summary.New != 0 {
			t.Errorf("new = %d, want 0", diff.Summary.New)
		}
		if diff.Summary.Absent != 0 {
			t.Errorf("absent = %d, want 0", diff.Summary.Absent)
		}
	})

	t.Run("regressed_count_and_ids", func(t *testing.T) {
		if diff.Summary.Regressed != 2 {
			t.Errorf("regressed = %d, want 2", diff.Summary.Regressed)
		}
		regressedIDs := make(map[string]bool)
		for _, req := range diff.RequirementDiffs {
			if req.State == types.StateRegressed {
				regressedIDs[req.ID] = true
			}
		}
		expectedRegressed := []string{"SV-260500", "SV-260601"}
		for _, id := range expectedRegressed {
			if !regressedIDs[id] {
				t.Errorf("expected %s to be regressed, but it was not", id)
			}
		}
	})

	t.Run("fixed_have_resultChanged", func(t *testing.T) {
		fixedReqs := filterByState(diff.RequirementDiffs, types.StateFixed)
		if len(fixedReqs) == 0 {
			t.Fatal("expected at least one fixed requirement")
		}
		for _, req := range fixedReqs {
			if !containsReason(req.ChangeReasons, types.ReasonResultChanged) {
				t.Errorf("fixed requirement %s missing resultChanged in changeReasons", req.ID)
			}
		}
	})

	t.Run("matched_have_before_after", func(t *testing.T) {
		for _, req := range diff.RequirementDiffs {
			if req.State == types.StateNew || req.State == types.StateAbsent {
				continue
			}
			if req.Before == nil {
				t.Errorf("requirement %s before is nil", req.ID)
			}
			if req.After == nil {
				t.Errorf("requirement %s after is nil", req.ID)
			}
		}
	})

	t.Run("sum_equals_total", func(t *testing.T) {
		s := diff.Summary
		sum := s.Fixed + s.Regressed + s.New + s.Absent + s.Unchanged + s.Updated
		if sum != s.Total {
			t.Errorf("sum of states (%d) != total (%d)", sum, s.Total)
		}
	})

	t.Run("formatVersion_and_mode", func(t *testing.T) {
		if diff.FormatVersion != version100 {
			t.Errorf("formatVersion = %q, want %q", diff.FormatVersion, version100)
		}
		if diff.ComparisonMode != types.ModeTemporal {
			t.Errorf("comparisonMode = %q, want %q", diff.ComparisonMode, types.ModeTemporal)
		}
	})
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

func assertSummary(
	t *testing.T,
	s types.ComparisonSummary,
	wantFixed, wantRegressed, wantNew, wantAbsent, wantUnchanged, wantUpdated int,
	wantTotal, wantMatched, wantUnmatchedOld, wantUnmatchedNew int,
) {
	t.Helper()
	if s.Fixed != wantFixed {
		t.Errorf("summary.fixed = %d, want %d", s.Fixed, wantFixed)
	}
	if s.Regressed != wantRegressed {
		t.Errorf("summary.regressed = %d, want %d", s.Regressed, wantRegressed)
	}
	if s.New != wantNew {
		t.Errorf("summary.new = %d, want %d", s.New, wantNew)
	}
	if s.Absent != wantAbsent {
		t.Errorf("summary.absent = %d, want %d", s.Absent, wantAbsent)
	}
	if s.Unchanged != wantUnchanged {
		t.Errorf("summary.unchanged = %d, want %d", s.Unchanged, wantUnchanged)
	}
	if s.Updated != wantUpdated {
		t.Errorf("summary.updated = %d, want %d", s.Updated, wantUpdated)
	}
	if s.Total != wantTotal {
		t.Errorf("summary.total = %d, want %d", s.Total, wantTotal)
	}
	if s.MatchedCount != wantMatched {
		t.Errorf("summary.matchedCount = %d, want %d", s.MatchedCount, wantMatched)
	}
	if s.UnmatchedOldCount != wantUnmatchedOld {
		t.Errorf("summary.unmatchedOldCount = %d, want %d", s.UnmatchedOldCount, wantUnmatchedOld)
	}
	if s.UnmatchedNewCount != wantUnmatchedNew {
		t.Errorf("summary.unmatchedNewCount = %d, want %d", s.UnmatchedNewCount, wantUnmatchedNew)
	}
}

func assertState(t *testing.T, req *types.RequirementDiff, want types.RequirementState) {
	t.Helper()
	if req.State != want {
		t.Errorf("requirement %s state = %q, want %q", req.ID, req.State, want)
	}
}

func assertStatuses(t *testing.T, req *types.RequirementDiff, wantOld, wantNew string) {
	t.Helper()
	if req.OldEffectiveStatus != wantOld {
		t.Errorf("requirement %s oldEffectiveStatus = %q, want %q", req.ID, req.OldEffectiveStatus, wantOld)
	}
	if req.NewEffectiveStatus != wantNew {
		t.Errorf("requirement %s newEffectiveStatus = %q, want %q", req.ID, req.NewEffectiveStatus, wantNew)
	}
}

//nolint:unparam // state is intentionally a parameter for reuse across test files.
func filterByState(diffs []types.RequirementDiff, state types.RequirementState) []types.RequirementDiff {
	var result []types.RequirementDiff
	for _, d := range diffs {
		if d.State == state {
			result = append(result, d)
		}
	}
	return result
}
