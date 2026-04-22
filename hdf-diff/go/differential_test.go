package diff

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

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

// fixturesDir returns the absolute path to the shared test fixtures directory.
// The fixtures live in hdf-diff/test/fixtures/ (sibling monorepo package).
func fixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// From hdf-diff/go/ up to hdf-diff/, then into test/fixtures
	dir := filepath.Join(filepath.Dir(filename), "..", "test", "fixtures")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("filepath.Abs failed: %v", err)
	}
	return absDir
}

// loadV2Fixture loads a v2-format HDF JSON fixture into hdf.HDFResults.
func loadV2Fixture(t *testing.T, name string) hdf.HDFResults {
	t.Helper()
	path := filepath.Join(fixturesDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s not found: %v (run from monorepo root)", name, err)
	}
	result, err := hdf.UnmarshalHDFResults(data)
	if err != nil {
		t.Fatalf("failed to parse v2 fixture %s: %v", name, err)
	}
	return result
}

// loadV1Fixture loads a v1-format InSpec exec-json fixture, normalizes it to v2,
// and returns hdf.HDFResults.
func loadV1Fixture(t *testing.T, name string) hdf.HDFResults {
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
	if !IsV1Format(raw) {
		t.Fatalf("expected %s to be v1 format", name)
	}

	result, warnings, err := ToV2(data)
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

	comp, err := DiffHdf(oldDoc, []hdf.HDFResults{newDoc}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	// ── Top-level structure ──────────────────────────────────────────────
	t.Run("formatVersion", func(t *testing.T) {
		if comp.FormatVersion != version100 {
			t.Errorf("formatVersion = %q, want %q", comp.FormatVersion, version100)
		}
	})

	t.Run("comparisonMode", func(t *testing.T) {
		if comp.ComparisonMode != ModeTemporal {
			t.Errorf("comparisonMode = %q, want %q", comp.ComparisonMode, ModeTemporal)
		}
	})

	t.Run("sources", func(t *testing.T) {
		if len(comp.Sources) != 2 {
			t.Fatalf("sources length = %d, want 2", len(comp.Sources))
		}
		if comp.Sources[0].Role != RoleOld {
			t.Errorf("sources[0].role = %q, want %q", comp.Sources[0].Role, RoleOld)
		}
		if comp.Sources[1].Role != RoleNew {
			t.Errorf("sources[1].role = %q, want %q", comp.Sources[1].Role, RoleNew)
		}
	})

	t.Run("matching", func(t *testing.T) {
		if comp.Matching == nil {
			t.Fatal("matching is nil")
		}
		if comp.Matching.PrimaryStrategy != stratExactID {
			t.Errorf("matching.primaryStrategy = %q, want %q", comp.Matching.PrimaryStrategy, stratExactID)
		}
	})

	// ── comp.Summary counts ───────────────────────────────────────────────────
	t.Run("summary", func(t *testing.T) {
		s := comp.Summary
		assertSummary(t, s, 1, 1, 1, 1, 1, 1, 6, 4, 1, 1)
	})

	// ── Per-requirement assertions ───────────────────────────────────────
	t.Run("SV-001_fixed", func(t *testing.T) {
		req := findReq(comp.RequirementDiffs, "SV-001")
		if req == nil {
			t.Fatal("SV-001 not found")
		}
		assertState(t, req, StateFixed)
		assertStatuses(t, req, "failed", "passed")
		if !containsReason(req.ChangeReasons, ReasonResultChanged) {
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
		req := findReq(comp.RequirementDiffs, "SV-002")
		if req == nil {
			t.Fatal("SV-002 not found")
		}
		assertState(t, req, StateUnchanged)
		assertStatuses(t, req, "passed", "passed")
		if len(req.FieldChanges) != 0 {
			t.Errorf("fieldChanges should be empty, got %d", len(req.FieldChanges))
		}
		if len(req.ChangeReasons) != 0 {
			t.Errorf("changeReasons should be empty, got %v", req.ChangeReasons)
		}
	})

	t.Run("SV-003_regressed", func(t *testing.T) {
		req := findReq(comp.RequirementDiffs, "SV-003")
		if req == nil {
			t.Fatal("SV-003 not found")
		}
		assertState(t, req, StateRegressed)
		assertStatuses(t, req, "passed", "failed")
		if !containsReason(req.ChangeReasons, ReasonResultChanged) {
			t.Error("expected resultChanged in changeReasons")
		}
	})

	t.Run("SV-004_absent", func(t *testing.T) {
		req := findReq(comp.RequirementDiffs, "SV-004")
		if req == nil {
			t.Fatal("SV-004 not found")
		}
		assertState(t, req, StateAbsent)
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
		req := findReq(comp.RequirementDiffs, "SV-005")
		if req == nil {
			t.Fatal("SV-005 not found")
		}
		assertState(t, req, StateUpdated)
		if !containsReason(req.ChangeReasons, ReasonImpactChanged) {
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
			if fc.Path == "impact" && fc.Op == OpReplace {
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
		req := findReq(comp.RequirementDiffs, "SV-006")
		if req == nil {
			t.Fatal("SV-006 not found")
		}
		assertState(t, req, StateNew)
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
		if len(comp.BaselineDiffs) != 1 {
			t.Fatalf("baselineDiffs length = %d, want 1", len(comp.BaselineDiffs))
		}
		bd := comp.BaselineDiffs[0]
		if bd.Name != "rhel9-stig-baseline" {
			t.Errorf("baseline name = %q, want %q", bd.Name, "rhel9-stig-baseline")
		}
		if bd.OldVersion != version100 {
			t.Errorf("oldVersion = %q, want %q", bd.OldVersion, version100)
		}
		if bd.NewVersion != "1.1.0" {
			t.Errorf("newVersion = %q, want %q", bd.NewVersion, "1.1.0")
		}
		if bd.State != StateUpdated {
			t.Errorf("state = %q, want %q", bd.State, StateUpdated)
		}
	})

	// ── Requirement ordering (sorted by ID) ──────────────────────────────
	t.Run("sorted_by_id", func(t *testing.T) {
		for i := 1; i < len(comp.RequirementDiffs); i++ {
			prev := comp.RequirementDiffs[i-1].ID
			curr := comp.RequirementDiffs[i].ID
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

	comp, err := DiffHdf(doc, []hdf.HDFResults{doc}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	t.Run("summary", func(t *testing.T) {
		assertSummary(t, comp.Summary, 0, 0, 0, 0, 5, 0, 5, 5, 0, 0)
	})

	t.Run("all_unchanged", func(t *testing.T) {
		for _, req := range comp.RequirementDiffs {
			if req.State != StateUnchanged {
				t.Errorf("requirement %s state = %q, want %q", req.ID, req.State, StateUnchanged)
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

	comp, err := DiffHdf(oldDoc, []hdf.HDFResults{newDoc}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	t.Run("summary", func(t *testing.T) {
		assertSummary(t, comp.Summary, 1, 0, 0, 4, 0, 0, 5, 1, 4, 0)
	})

	t.Run("SV-001_overrideAdded", func(t *testing.T) {
		req := findReq(comp.RequirementDiffs, "SV-001")
		if req == nil {
			t.Fatal("SV-001 not found")
		}
		assertState(t, req, StateFixed)
		assertStatuses(t, req, "failed", "passed")
		if !containsReason(req.ChangeReasons, ReasonOverrideAdded) {
			t.Errorf("expected overrideAdded in changeReasons, got %v", req.ChangeReasons)
		}
	})

	t.Run("absent_requirements", func(t *testing.T) {
		for _, id := range []string{"SV-002", "SV-003", "SV-004", "SV-005"} {
			req := findReq(comp.RequirementDiffs, id)
			if req == nil {
				t.Errorf("%s not found", id)
				continue
			}
			if req.State != StateAbsent {
				t.Errorf("%s state = %q, want %q", id, req.State, StateAbsent)
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

	comp, err := DiffHdf(nginxFailing, []hdf.HDFResults{nginxClean}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	t.Run("total", func(t *testing.T) {
		if comp.Summary.Total != 41 {
			t.Errorf("total = %d, want 41", comp.Summary.Total)
		}
	})

	t.Run("summary", func(t *testing.T) {
		assertSummary(t, comp.Summary, 3, 0, 0, 0, 38, 0, 41, 41, 0, 0)
	})

	t.Run("no_new_or_absent", func(t *testing.T) {
		for _, req := range comp.RequirementDiffs {
			if req.State == StateNew || req.State == StateAbsent {
				t.Errorf("requirement %s has unexpected state %q", req.ID, req.State)
			}
		}
	})

	t.Run("no_regressions", func(t *testing.T) {
		if comp.Summary.Regressed != 0 {
			t.Errorf("regressed = %d, want 0", comp.Summary.Regressed)
		}
	})

	t.Run("fixed_have_resultChanged", func(t *testing.T) {
		fixedReqs := filterByState(comp.RequirementDiffs, StateFixed)
		if len(fixedReqs) == 0 {
			t.Fatal("expected at least one fixed requirement")
		}
		for _, req := range fixedReqs {
			if !containsReason(req.ChangeReasons, ReasonResultChanged) {
				t.Errorf("fixed requirement %s missing resultChanged in changeReasons", req.ID)
			}
		}
	})

	t.Run("matched_have_before_after", func(t *testing.T) {
		for _, req := range comp.RequirementDiffs {
			if req.State == StateNew || req.State == StateAbsent {
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
		if comp.FormatVersion != version100 {
			t.Errorf("formatVersion = %q, want %q", comp.FormatVersion, version100)
		}
		if comp.ComparisonMode != ModeTemporal {
			t.Errorf("comparisonMode = %q, want %q", comp.ComparisonMode, ModeTemporal)
		}
	})

	t.Run("sum_equals_total", func(t *testing.T) {
		s := comp.Summary
		sum := s.Fixed + s.Regressed + s.New + s.Absent + s.Unchanged + s.Updated
		if sum != s.Total {
			t.Errorf("sum of states (%d) != total (%d)", sum, s.Total)
		}
	})

	t.Run("baseline_matched", func(t *testing.T) {
		if len(comp.BaselineDiffs) == 0 {
			t.Error("expected at least one baseline diff")
		} else if comp.BaselineDiffs[0].Name == "" {
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

	comp, err := DiffHdf(vanilla, []hdf.HDFResults{hardened}, Options{})
	if err != nil {
		t.Fatalf("DiffHdf returned error: %v", err)
	}

	t.Run("total", func(t *testing.T) {
		if comp.Summary.Total != 192 {
			t.Errorf("total = %d, want 192", comp.Summary.Total)
		}
	})

	t.Run("summary", func(t *testing.T) {
		assertSummary(t, comp.Summary, 95, 2, 0, 0, 95, 0, 192, 192, 0, 0)
	})

	t.Run("no_new_or_absent", func(t *testing.T) {
		if comp.Summary.New != 0 {
			t.Errorf("new = %d, want 0", comp.Summary.New)
		}
		if comp.Summary.Absent != 0 {
			t.Errorf("absent = %d, want 0", comp.Summary.Absent)
		}
	})

	t.Run("regressed_count_and_ids", func(t *testing.T) {
		if comp.Summary.Regressed != 2 {
			t.Errorf("regressed = %d, want 2", comp.Summary.Regressed)
		}
		regressedIDs := make(map[string]bool)
		for _, req := range comp.RequirementDiffs {
			if req.State == StateRegressed {
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
		fixedReqs := filterByState(comp.RequirementDiffs, StateFixed)
		if len(fixedReqs) == 0 {
			t.Fatal("expected at least one fixed requirement")
		}
		for _, req := range fixedReqs {
			if !containsReason(req.ChangeReasons, ReasonResultChanged) {
				t.Errorf("fixed requirement %s missing resultChanged in changeReasons", req.ID)
			}
		}
	})

	t.Run("matched_have_before_after", func(t *testing.T) {
		for _, req := range comp.RequirementDiffs {
			if req.State == StateNew || req.State == StateAbsent {
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
		s := comp.Summary
		sum := s.Fixed + s.Regressed + s.New + s.Absent + s.Unchanged + s.Updated
		if sum != s.Total {
			t.Errorf("sum of states (%d) != total (%d)", sum, s.Total)
		}
	})

	t.Run("formatVersion_and_mode", func(t *testing.T) {
		if comp.FormatVersion != version100 {
			t.Errorf("formatVersion = %q, want %q", comp.FormatVersion, version100)
		}
		if comp.ComparisonMode != ModeTemporal {
			t.Errorf("comparisonMode = %q, want %q", comp.ComparisonMode, ModeTemporal)
		}
	})
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

func assertSummary(
	t *testing.T,
	s ComparisonSummary,
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

func assertState(t *testing.T, req *RequirementDiff, want RequirementState) {
	t.Helper()
	if req.State != want {
		t.Errorf("requirement %s state = %q, want %q", req.ID, req.State, want)
	}
}

func assertStatuses(t *testing.T, req *RequirementDiff, wantOld, wantNew string) {
	t.Helper()
	if req.OldEffectiveStatus != wantOld {
		t.Errorf("requirement %s oldEffectiveStatus = %q, want %q", req.ID, req.OldEffectiveStatus, wantOld)
	}
	if req.NewEffectiveStatus != wantNew {
		t.Errorf("requirement %s newEffectiveStatus = %q, want %q", req.ID, req.NewEffectiveStatus, wantNew)
	}
}

//nolint:unparam // state is intentionally a parameter for reuse across test files.
func filterByState(diffs []RequirementDiff, state RequirementState) []RequirementDiff {
	var result []RequirementDiff
	for _, d := range diffs {
		if d.State == state {
			result = append(result, d)
		}
	}
	return result
}
