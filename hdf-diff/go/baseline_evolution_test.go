package diff

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ── Test helpers ─────────────────────────────────────────────────────

func makeBaselineReq(id, title string, impact float64, descs []hdf.Description, tags map[string]any) hdf.BaselineRequirement {
	return hdf.BaselineRequirement{
		ID:           id,
		Title:        strPtr(title),
		Impact:       impact,
		Descriptions: descs,
		Tags:         tags,
		Refs:         []hdf.Reference{},
	}
}

func makeHdfBaseline(name, version string, reqs ...hdf.BaselineRequirement) hdf.HDFBaseline {
	return hdf.HDFBaseline{
		Name:         name,
		Version:      strPtr(version),
		Requirements: reqs,
		Groups:       []hdf.RequirementGroup{},
		Supports:     []hdf.SupportedPlatform{},
		Depends:      []hdf.Dependency{},
		Integrity:    &hdf.Integrity{},
	}
}

// ── Fixtures ─────────────────────────────────────────────────────────

func baselineV1Fixture() hdf.HDFBaseline {
	return makeHdfBaseline("test-stig", "1.0",
		makeBaselineReq("SV-001", "Old Title", 0.7,
			[]hdf.Description{{Label: "default", Data: "Check X"}},
			map[string]any{"nist": []any{"AC-1"}},
		),
		makeBaselineReq("SV-002", "Unchanged", 0.5,
			[]hdf.Description{{Label: "default", Data: "Check Y"}},
			map[string]any{"nist": []any{"AC-2"}},
		),
		makeBaselineReq("SV-003", "Removed", 0.3,
			[]hdf.Description{},
			map[string]any{},
		),
	)
}

func baselineV2Fixture() hdf.HDFBaseline {
	return makeHdfBaseline("test-stig", "2.0",
		makeBaselineReq("SV-001", "New Title", 0.9,
			[]hdf.Description{{Label: "default", Data: "Check X revised"}},
			map[string]any{"nist": []any{"AC-1", "AC-1 (1)"}},
		),
		makeBaselineReq("SV-002", "Unchanged", 0.5,
			[]hdf.Description{{Label: "default", Data: "Check Y"}},
			map[string]any{"nist": []any{"AC-2"}},
		),
		makeBaselineReq("SV-004", "Added", 0.7,
			[]hdf.Description{},
			map[string]any{},
		),
	)
}

// ── Tests ────────────────────────────────────────────────────────────

func TestDiffBaselines_ComparisonMode(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ComparisonMode != ModeBaselineEvolution {
		t.Errorf("expected comparisonMode %q, got %q", ModeBaselineEvolution, result.ComparisonMode)
	}
}

func TestDiffBaselines_FormatVersion(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FormatVersion != "1.0.0" {
		t.Errorf("expected formatVersion %q, got %q", "1.0.0", result.FormatVersion)
	}
}

func TestDiffBaselines_Timestamp(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Timestamp == "" {
		t.Error("expected timestamp to be set")
	}
}

func TestDiffBaselines_Sources(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(result.Sources))
	}
	if result.Sources[0].Role != RoleOld {
		t.Errorf("expected source[0] role %q, got %q", RoleOld, result.Sources[0].Role)
	}
	if result.Sources[1].Role != RoleNew {
		t.Errorf("expected source[1] role %q, got %q", RoleNew, result.Sources[1].Role)
	}
	if result.Sources[0].Label != "test-stig 1.0" {
		t.Errorf("expected source[0] label %q, got %q", "test-stig 1.0", result.Sources[0].Label)
	}
	if result.Sources[1].Label != "test-stig 2.0" {
		t.Errorf("expected source[1] label %q, got %q", "test-stig 2.0", result.Sources[1].Label)
	}
}

func TestDiffBaselines_BaselineDiffs(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.BaselineDiffs) != 1 {
		t.Fatalf("expected 1 baseline diff, got %d", len(result.BaselineDiffs))
	}
	bd := result.BaselineDiffs[0]
	if bd.Name != "test-stig" {
		t.Errorf("expected baseline name %q, got %q", "test-stig", bd.Name)
	}
	if bd.OldVersion != "1.0" {
		t.Errorf("expected oldVersion %q, got %q", "1.0", bd.OldVersion)
	}
	if bd.NewVersion != "2.0" {
		t.Errorf("expected newVersion %q, got %q", "2.0", bd.NewVersion)
	}
	if bd.State != StateUpdated {
		t.Errorf("expected baseline state %q, got %q", StateUpdated, bd.State)
	}
}

func TestDiffBaselines_BaselineDiffsUnchanged(t *testing.T) {
	v1 := baselineV1Fixture()
	result, err := DiffBaselines(v1, v1, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.BaselineDiffs) != 1 {
		t.Fatalf("expected 1 baseline diff, got %d", len(result.BaselineDiffs))
	}
	if result.BaselineDiffs[0].State != StateUnchanged {
		t.Errorf("expected baseline state %q, got %q", StateUnchanged, result.BaselineDiffs[0].State)
	}
}

func TestDiffBaselines_SV001Updated(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := findReq(result.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	if req.State != StateUpdated {
		t.Errorf("expected SV-001 state %q, got %q", StateUpdated, req.State)
	}
}

func TestDiffBaselines_SV002Unchanged(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := findReq(result.RequirementDiffs, "SV-002")
	if req == nil {
		t.Fatal("SV-002 not found")
	}
	if req.State != StateUnchanged {
		t.Errorf("expected SV-002 state %q, got %q", StateUnchanged, req.State)
	}
}

func TestDiffBaselines_AbsentAndNew(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		id            string
		expectedState RequirementState
		beforeNil     bool
		afterNil      bool
	}{
		{"SV-003", StateAbsent, false, true},
		{"SV-004", StateNew, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			req := findReq(result.RequirementDiffs, tc.id)
			if req == nil {
				t.Fatalf("%s not found", tc.id)
			}
			if req.State != tc.expectedState {
				t.Errorf("expected state %q, got %q", tc.expectedState, req.State)
			}
			if tc.beforeNil && req.Before != nil {
				t.Error("expected before to be nil")
			}
			if !tc.beforeNil && req.Before == nil {
				t.Error("expected before to be non-nil")
			}
			if tc.afterNil && req.After != nil {
				t.Error("expected after to be nil")
			}
			if !tc.afterNil && req.After == nil {
				t.Error("expected after to be non-nil")
			}
		})
	}
}

func TestDiffBaselines_FieldChanges(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := findReq(result.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	if len(req.FieldChanges) < 4 {
		t.Errorf("expected at least 4 field changes, got %d", len(req.FieldChanges))
	}

	changedPaths := make(map[string]bool)
	for _, fc := range req.FieldChanges {
		changedPaths[fc.Path] = true
	}

	for _, expectedPath := range []string{"title", "impact", "descriptions", "tags"} {
		if !changedPaths[expectedPath] {
			t.Errorf("expected field change for %q, not found", expectedPath)
		}
	}
}

func TestDiffBaselines_ChangeReasons(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SV-001: should have impactChanged and metadataChanged
	req := findReq(result.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	hasImpactChanged := false
	hasMetadataChanged := false
	for _, r := range req.ChangeReasons {
		if r == ReasonImpactChanged {
			hasImpactChanged = true
		}
		if r == ReasonMetadataChanged {
			hasMetadataChanged = true
		}
	}
	if !hasImpactChanged {
		t.Error("expected impactChanged in SV-001 change reasons")
	}
	if !hasMetadataChanged {
		t.Error("expected metadataChanged in SV-001 change reasons")
	}

	// SV-002: should have no change reasons
	req2 := findReq(result.RequirementDiffs, "SV-002")
	if req2 == nil {
		t.Fatal("SV-002 not found")
	}
	if len(req2.ChangeReasons) != 0 {
		t.Errorf("expected 0 change reasons for SV-002, got %d", len(req2.ChangeReasons))
	}
}

func TestDiffBaselines_SummaryCounts(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.Summary
	if s.Total != 4 {
		t.Errorf("expected total 4, got %d", s.Total)
	}
	if s.MatchedCount != 2 {
		t.Errorf("expected matchedCount 2, got %d", s.MatchedCount)
	}
	if s.UnmatchedOldCount != 1 {
		t.Errorf("expected unmatchedOldCount 1, got %d", s.UnmatchedOldCount)
	}
	if s.UnmatchedNewCount != 1 {
		t.Errorf("expected unmatchedNewCount 1, got %d", s.UnmatchedNewCount)
	}
	if s.Updated != 1 {
		t.Errorf("expected updated 1, got %d", s.Updated)
	}
	if s.Unchanged != 1 {
		t.Errorf("expected unchanged 1, got %d", s.Unchanged)
	}
	if s.Absent != 1 {
		t.Errorf("expected absent 1, got %d", s.Absent)
	}
	if s.New != 1 {
		t.Errorf("expected new 1, got %d", s.New)
	}
	if s.Fixed != 0 {
		t.Errorf("expected fixed 0, got %d", s.Fixed)
	}
	if s.Regressed != 0 {
		t.Errorf("expected regressed 0, got %d", s.Regressed)
	}
}

func TestDiffBaselines_MatchingConfig(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Matching == nil {
		t.Fatal("expected matching config to be set")
	}
	if result.Matching.PrimaryStrategy != "exactId" {
		t.Errorf("expected primaryStrategy %q, got %q", "exactId", result.Matching.PrimaryStrategy)
	}

	req := findReq(result.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	if req.MatchStrategy != "exactId" {
		t.Errorf("expected matchStrategy %q, got %q", "exactId", req.MatchStrategy)
	}
	if req.MatchConfidence == nil || *req.MatchConfidence != 1.0 {
		t.Error("expected matchConfidence 1.0")
	}
}

func TestDiffBaselines_IdenticalBaselines(t *testing.T) {
	v1 := baselineV1Fixture()
	result, err := DiffBaselines(v1, v1, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, req := range result.RequirementDiffs {
		if req.State != StateUnchanged {
			t.Errorf("expected all requirements unchanged, got %q for %s", req.State, req.ID)
		}
	}
}

func TestDiffBaselines_BeforeAfterSnapshots(t *testing.T) {
	result, err := DiffBaselines(baselineV1Fixture(), baselineV2Fixture(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := findReq(result.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	if req.Before == nil {
		t.Fatal("expected before snapshot")
	}
	if req.After == nil {
		t.Fatal("expected after snapshot")
	}
	if req.Before.Title == nil || *req.Before.Title != "Old Title" {
		t.Error("expected before title 'Old Title'")
	}
	if req.After.Title == nil || *req.After.Title != "New Title" {
		t.Error("expected after title 'New Title'")
	}
}
