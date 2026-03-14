package engine

import (
	"sort"
	"testing"
	"time"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// ---------------------------------------------------------------------------
// Constants used across tests
// ---------------------------------------------------------------------------

const (
	statusFailed  = "failed"
	statusPassed  = "passed"
	version100    = "1.0.0"
	version110    = "1.1.0"
	version200    = "2.0.0"
	stratExactID  = "exactId"
	fieldImpact   = "impact"
	fieldSeverity = "severity"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func strPtr(s string) *string { return &s }

func makeRequirement(id string, status hdf.ResultStatus, impact float64) hdf.EvaluatedRequirement {
	s := status
	return hdf.EvaluatedRequirement{
		ID:           id,
		Impact:       impact,
		Tags:         map[string]interface{}{},
		Descriptions: []hdf.Description{{Label: "default", Data: "test"}},
		Results: []hdf.RequirementResult{{
			Status:    &s,
			CodeDesc:  "test",
			StartTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		}},
	}
}

func makeRequirementWithTitle(id, title string, status hdf.ResultStatus, impact float64) hdf.EvaluatedRequirement {
	req := makeRequirement(id, status, impact)
	req.Title = strPtr(title)
	return req
}

func makeBaseline(name, version string, reqs ...hdf.EvaluatedRequirement) hdf.EvaluatedBaseline {
	return hdf.EvaluatedBaseline{
		Name:         name,
		Version:      strPtr(version),
		Requirements: reqs,
		Groups:       []hdf.RequirementGroup{},
		Supports:     []hdf.SupportedPlatform{},
		Checksum:     hdf.Checksum{Algorithm: "sha256", Value: "abc123"},
		Depends:      []hdf.Dependency{},
		Attributes:   []map[string]interface{}{},
	}
}

func makeResults(baselines ...hdf.EvaluatedBaseline) hdf.HdfResults {
	return hdf.HdfResults{Baselines: baselines}
}

func findReq(diffs []types.RequirementDiff, id string) *types.RequirementDiff {
	for i := range diffs {
		if diffs[i].ID == id {
			return &diffs[i]
		}
	}
	return nil
}

func findBaselineDiff(diffs []types.BaselineDiff, name string) *types.BaselineDiff {
	for i := range diffs {
		if diffs[i].Name == name {
			return &diffs[i]
		}
	}
	return nil
}

func defaultOpts() Options {
	return Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: types.ModeTemporal,
		MatchStrategy:  stratExactID,
	}
}

// assertAbsentAndNewSlicesEmpty validates that both changeReasons and fieldChanges
// are empty for absent and new requirements. Shared helper eliminates duplication.
func assertAbsentAndNewSlicesEmpty(
	t *testing.T,
	comp types.HdfComparison,
	checkChangeReasons bool,
	checkFieldChanges bool,
) {
	t.Helper()

	absent := findReq(comp.RequirementDiffs, "SV-001")
	if absent == nil {
		t.Fatal("SV-001 not found")
	}
	if checkChangeReasons && len(absent.ChangeReasons) != 0 {
		t.Errorf("expected empty changeReasons for absent, got %v", absent.ChangeReasons)
	}
	if checkFieldChanges && len(absent.FieldChanges) != 0 {
		t.Errorf("expected empty fieldChanges for absent, got %v", absent.FieldChanges)
	}

	newReq := findReq(comp.RequirementDiffs, "SV-002")
	if newReq == nil {
		t.Fatal("SV-002 not found")
	}
	if checkChangeReasons && len(newReq.ChangeReasons) != 0 {
		t.Errorf("expected empty changeReasons for new, got %v", newReq.ChangeReasons)
	}
	if checkFieldChanges && len(newReq.FieldChanges) != 0 {
		t.Errorf("expected empty fieldChanges for new, got %v", newReq.FieldChanges)
	}
}

func buildAbsentAndNewComparison() types.HdfComparison {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-002", hdf.Passed, 0.7),
	)
	return DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())
}

// ---------------------------------------------------------------------------
// 1. Identical documents -> all unchanged
// ---------------------------------------------------------------------------

func TestIdenticalDocuments_AllUnchanged(t *testing.T) {
	baseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
		makeRequirement("SV-003", hdf.Passed, 0.7),
	)
	results := makeResults(baseline)

	comp := DiffHdf(results, []hdf.HdfResults{results}, defaultOpts())

	for _, req := range comp.RequirementDiffs {
		if req.State != types.StateUnchanged {
			t.Errorf("expected state 'unchanged' for %s, got %q", req.ID, req.State)
		}
	}
}

func TestIdenticalDocuments_SummaryCounts(t *testing.T) {
	baseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
		makeRequirement("SV-003", hdf.Passed, 0.7),
		makeRequirement("SV-004", hdf.Failed, 0.7),
		makeRequirement("SV-005", hdf.Passed, 0.3),
	)
	results := makeResults(baseline)

	comp := DiffHdf(results, []hdf.HdfResults{results}, defaultOpts())

	if comp.Summary.Fixed != 0 {
		t.Errorf("expected fixed=0, got %d", comp.Summary.Fixed)
	}
	if comp.Summary.Regressed != 0 {
		t.Errorf("expected regressed=0, got %d", comp.Summary.Regressed)
	}
	if comp.Summary.New != 0 {
		t.Errorf("expected new=0, got %d", comp.Summary.New)
	}
	if comp.Summary.Absent != 0 {
		t.Errorf("expected absent=0, got %d", comp.Summary.Absent)
	}
	if comp.Summary.Updated != 0 {
		t.Errorf("expected updated=0, got %d", comp.Summary.Updated)
	}
	if comp.Summary.Unchanged != 5 {
		t.Errorf("expected unchanged=5, got %d", comp.Summary.Unchanged)
	}
	if comp.Summary.Total != 5 {
		t.Errorf("expected total=5, got %d", comp.Summary.Total)
	}
	if comp.Summary.MatchedCount != 5 {
		t.Errorf("expected matchedCount=5, got %d", comp.Summary.MatchedCount)
	}
	if comp.Summary.UnmatchedOldCount != 0 {
		t.Errorf("expected unmatchedOldCount=0, got %d", comp.Summary.UnmatchedOldCount)
	}
	if comp.Summary.UnmatchedNewCount != 0 {
		t.Errorf("expected unmatchedNewCount=0, got %d", comp.Summary.UnmatchedNewCount)
	}
}

// ---------------------------------------------------------------------------
// 2. Fixed requirement (old=failed, new=passed)
// ---------------------------------------------------------------------------

func TestFixedRequirement(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found in diffs")
	}
	if req.State != types.StateFixed {
		t.Errorf("expected state 'fixed', got %q", req.State)
	}
	if req.OldEffectiveStatus != statusFailed {
		t.Errorf("expected oldEffectiveStatus %q, got %q", statusFailed, req.OldEffectiveStatus)
	}
	if req.NewEffectiveStatus != statusPassed {
		t.Errorf("expected newEffectiveStatus %q, got %q", statusPassed, req.NewEffectiveStatus)
	}
	if req.Before == nil {
		t.Error("expected before snapshot to be non-nil")
	}
	if req.After == nil {
		t.Error("expected after snapshot to be non-nil")
	}
}

// ---------------------------------------------------------------------------
// 3. Regressed requirement (old=passed, new=failed)
// ---------------------------------------------------------------------------

func TestRegressedRequirement(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found in diffs")
	}
	if req.State != types.StateRegressed {
		t.Errorf("expected state 'regressed', got %q", req.State)
	}
	if req.OldEffectiveStatus != statusPassed {
		t.Errorf("expected oldEffectiveStatus %q, got %q", statusPassed, req.OldEffectiveStatus)
	}
	if req.NewEffectiveStatus != statusFailed {
		t.Errorf("expected newEffectiveStatus %q, got %q", statusFailed, req.NewEffectiveStatus)
	}
}

// ---------------------------------------------------------------------------
// 4. New requirement (only in new)
// ---------------------------------------------------------------------------

func TestNewRequirement(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "New control", hdf.Passed, 0.5),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-002")
	if req == nil {
		t.Fatal("SV-002 not found in diffs")
	}
	if req.State != types.StateNew {
		t.Errorf("expected state 'new', got %q", req.State)
	}
	if req.Before != nil {
		t.Error("expected before to be nil for new requirement")
	}
	if req.After == nil {
		t.Error("expected after to be non-nil for new requirement")
	}
	if req.OldEffectiveStatus != "" {
		t.Errorf("expected empty oldEffectiveStatus, got %q", req.OldEffectiveStatus)
	}
	if req.NewEffectiveStatus != statusPassed {
		t.Errorf("expected newEffectiveStatus %q, got %q", statusPassed, req.NewEffectiveStatus)
	}
}

// ---------------------------------------------------------------------------
// 5. Absent requirement (only in old)
// ---------------------------------------------------------------------------

func TestAbsentRequirement(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Removed control", hdf.Failed, 0.5),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-002")
	if req == nil {
		t.Fatal("SV-002 not found in diffs")
	}
	if req.State != types.StateAbsent {
		t.Errorf("expected state 'absent', got %q", req.State)
	}
	if req.Before == nil {
		t.Error("expected before to be non-nil for absent requirement")
	}
	if req.After != nil {
		t.Error("expected after to be nil for absent requirement")
	}
	if req.OldEffectiveStatus != statusFailed {
		t.Errorf("expected oldEffectiveStatus %q, got %q", statusFailed, req.OldEffectiveStatus)
	}
	if req.NewEffectiveStatus != "" {
		t.Errorf("expected empty newEffectiveStatus, got %q", req.NewEffectiveStatus)
	}
}

// ---------------------------------------------------------------------------
// 6. Updated requirement (impact changed)
// ---------------------------------------------------------------------------

func TestUpdatedRequirement_ImpactChanged(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.3),
	)
	newReq := makeRequirement("SV-001", hdf.Passed, 0.0)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found in diffs")
	}
	// Impact changed from 0.3 (passed) to 0.0 (notApplicable) -> "updated" state
	if req.State != types.StateUpdated {
		t.Errorf("expected state 'updated', got %q", req.State)
	}

	foundImpactChanged := false
	for _, reason := range req.ChangeReasons {
		if reason == types.ReasonImpactChanged {
			foundImpactChanged = true
			break
		}
	}
	if !foundImpactChanged {
		t.Errorf("expected changeReasons to contain 'impactChanged', got %v", req.ChangeReasons)
	}

	if req.OldImpact == nil || *req.OldImpact != 0.3 {
		t.Errorf("expected oldImpact=0.3, got %v", req.OldImpact)
	}
	if req.NewImpact == nil || *req.NewImpact != 0.0 {
		t.Errorf("expected newImpact=0.0, got %v", req.NewImpact)
	}
}

// ---------------------------------------------------------------------------
// 7. Summary counts (mixed scenario)
// ---------------------------------------------------------------------------

func TestSummaryCountsMixed(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
		makeRequirement("SV-003", hdf.Passed, 0.7),
		makeRequirement("SV-004", hdf.Failed, 0.7),
		makeRequirement("SV-005", hdf.Passed, 0.3),
	)
	newBaseline := makeBaseline("test-baseline", version110,
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
		makeRequirement("SV-003", hdf.Failed, 0.7),
		makeRequirement("SV-005", hdf.Passed, 0.0),
		makeRequirement("SV-006", hdf.Passed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	if comp.Summary.Fixed != 1 {
		t.Errorf("expected fixed=1, got %d", comp.Summary.Fixed)
	}
	if comp.Summary.Regressed != 1 {
		t.Errorf("expected regressed=1, got %d", comp.Summary.Regressed)
	}
	if comp.Summary.New != 1 {
		t.Errorf("expected new=1, got %d", comp.Summary.New)
	}
	if comp.Summary.Absent != 1 {
		t.Errorf("expected absent=1, got %d", comp.Summary.Absent)
	}
	if comp.Summary.Unchanged != 1 {
		t.Errorf("expected unchanged=1, got %d", comp.Summary.Unchanged)
	}
	if comp.Summary.Updated != 1 {
		t.Errorf("expected updated=1, got %d", comp.Summary.Updated)
	}
	if comp.Summary.Total != 6 {
		t.Errorf("expected total=6, got %d", comp.Summary.Total)
	}
	if comp.Summary.MatchedCount != 4 {
		t.Errorf("expected matchedCount=4, got %d", comp.Summary.MatchedCount)
	}
	if comp.Summary.UnmatchedOldCount != 1 {
		t.Errorf("expected unmatchedOldCount=1, got %d", comp.Summary.UnmatchedOldCount)
	}
	if comp.Summary.UnmatchedNewCount != 1 {
		t.Errorf("expected unmatchedNewCount=1, got %d", comp.Summary.UnmatchedNewCount)
	}
}

// ---------------------------------------------------------------------------
// 8. Baseline diff detected (version change)
// ---------------------------------------------------------------------------

func TestBaselineDiff_VersionChange(t *testing.T) {
	oldBaseline := makeBaseline("rhel9-stig-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("rhel9-stig-baseline", version110,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	if len(comp.BaselineDiffs) != 1 {
		t.Fatalf("expected 1 baseline diff, got %d", len(comp.BaselineDiffs))
	}

	bd := comp.BaselineDiffs[0]
	if bd.Name != "rhel9-stig-baseline" {
		t.Errorf("expected name 'rhel9-stig-baseline', got %q", bd.Name)
	}
	if bd.State != types.StateUpdated {
		t.Errorf("expected state 'updated', got %q", bd.State)
	}
	if bd.OldVersion != version100 {
		t.Errorf("expected oldVersion %q, got %q", version100, bd.OldVersion)
	}
	if bd.NewVersion != version110 {
		t.Errorf("expected newVersion %q, got %q", version110, bd.NewVersion)
	}
}

func TestBaselineDiff_NewAndAbsent(t *testing.T) {
	oldBaseline := makeBaseline("baseline-alpha", version100)
	newBaseline := makeBaseline("baseline-beta", version200)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	if len(comp.BaselineDiffs) != 2 {
		t.Fatalf("expected 2 baseline diffs, got %d", len(comp.BaselineDiffs))
	}

	alpha := findBaselineDiff(comp.BaselineDiffs, "baseline-alpha")
	if alpha == nil {
		t.Fatal("baseline-alpha not found")
	}
	if alpha.State != types.StateAbsent {
		t.Errorf("expected alpha state 'absent', got %q", alpha.State)
	}
	if alpha.OldVersion != version100 {
		t.Errorf("expected alpha oldVersion %q, got %q", version100, alpha.OldVersion)
	}
	if alpha.NewVersion != "" {
		t.Errorf("expected alpha newVersion empty, got %q", alpha.NewVersion)
	}

	beta := findBaselineDiff(comp.BaselineDiffs, "baseline-beta")
	if beta == nil {
		t.Fatal("baseline-beta not found")
	}
	if beta.State != types.StateNew {
		t.Errorf("expected beta state 'new', got %q", beta.State)
	}
	if beta.OldVersion != "" {
		t.Errorf("expected beta oldVersion empty, got %q", beta.OldVersion)
	}
	if beta.NewVersion != version200 {
		t.Errorf("expected beta newVersion %q, got %q", version200, beta.NewVersion)
	}
}

// ---------------------------------------------------------------------------
// 9. Requirements sorted by ID
// ---------------------------------------------------------------------------

func TestRequirementsSortedByID(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-003", hdf.Passed, 0.7),
		makeRequirement("SV-001", hdf.Failed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-003", hdf.Passed, 0.7),
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	ids := make([]string, len(comp.RequirementDiffs))
	for i, rd := range comp.RequirementDiffs {
		ids[i] = rd.ID
	}

	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)

	for i := range ids {
		if ids[i] != sorted[i] {
			t.Errorf("requirementDiffs not sorted by ID: got %v, want %v", ids, sorted)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// 10. Drift extraction
// ---------------------------------------------------------------------------

func TestDriftExtraction(t *testing.T) {
	// Old and new both "passed" but tags differ -> unchanged state + metadataChanged reason = drift
	oldReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	oldReq.Tags = map[string]interface{}{"cci": []interface{}{"CCI-000001"}}

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	newReq.Tags = map[string]interface{}{"cci": []interface{}{"CCI-000002"}}

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	// The requirement should be "unchanged" in status but have changeReasons
	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	if req.State != types.StateUnchanged {
		t.Errorf("expected state 'unchanged', got %q", req.State)
	}
	if len(req.ChangeReasons) == 0 {
		t.Error("expected non-empty changeReasons for drift requirement")
	}

	// Check drift array
	if len(comp.Drift) == 0 {
		t.Fatal("expected non-empty drift array")
	}
	driftReq := findReq(comp.Drift, "SV-001")
	if driftReq == nil {
		t.Fatal("SV-001 not found in drift")
	}
	if driftReq.State != types.StateUnchanged {
		t.Errorf("expected drift state 'unchanged', got %q", driftReq.State)
	}
}

// ---------------------------------------------------------------------------
// 11. Fleet mode
// ---------------------------------------------------------------------------

func TestFleetMode(t *testing.T) {
	reference := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
	))

	system1 := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
	))
	system2 := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirement("SV-002", hdf.Failed, 0.5),
	))

	opts := Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: types.ModeFleet,
		MatchStrategy:  stratExactID,
	}

	comp := DiffHdf(reference, []hdf.HdfResults{system1, system2}, opts)

	if comp.ComparisonMode != types.ModeFleet {
		t.Errorf("expected comparisonMode 'fleet', got %q", comp.ComparisonMode)
	}

	// Sources: reference + 2 systems = 3
	if len(comp.Sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(comp.Sources))
	}
	if comp.Sources[0].Role != types.RoleReference {
		t.Errorf("expected first source role 'reference', got %q", comp.Sources[0].Role)
	}
	if comp.Sources[1].Role != types.RoleSystem {
		t.Errorf("expected second source role 'system', got %q", comp.Sources[1].Role)
	}
	if comp.Sources[2].Role != types.RoleSystem {
		t.Errorf("expected third source role 'system', got %q", comp.Sources[2].Role)
	}

	// 2 reqs per system * 2 systems = 4 requirement diffs total
	if len(comp.RequirementDiffs) != 4 {
		t.Errorf("expected 4 requirement diffs in fleet mode, got %d", len(comp.RequirementDiffs))
	}

	// Check sourceIndex is set
	for _, rd := range comp.RequirementDiffs {
		if rd.SourceIndex == nil {
			t.Errorf("expected sourceIndex to be set for requirement %s in fleet mode", rd.ID)
		}
	}

	// SV-001 should be regressed in system1 (sourceIndex=1) and unchanged in system2 (sourceIndex=2)
	for _, rd := range comp.RequirementDiffs {
		if rd.ID == "SV-001" && rd.SourceIndex != nil && *rd.SourceIndex == 1 {
			if rd.State != types.StateRegressed {
				t.Errorf("expected SV-001 in system1 to be regressed, got %q", rd.State)
			}
		}
		if rd.ID == "SV-001" && rd.SourceIndex != nil && *rd.SourceIndex == 2 {
			if rd.State != types.StateUnchanged {
				t.Errorf("expected SV-001 in system2 to be unchanged, got %q", rd.State)
			}
		}
	}
}

func TestFleetMode_SortedByIDThenSourceIndex(t *testing.T) {
	reference := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-002", hdf.Passed, 0.5),
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))
	system1 := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-002", hdf.Passed, 0.5),
		makeRequirement("SV-001", hdf.Failed, 0.7),
	))
	system2 := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-002", hdf.Failed, 0.5),
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))

	opts := Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: types.ModeFleet,
		MatchStrategy:  stratExactID,
	}

	comp := DiffHdf(reference, []hdf.HdfResults{system1, system2}, opts)

	// Should be sorted by ID first, then sourceIndex
	for i := 1; i < len(comp.RequirementDiffs); i++ {
		prev := comp.RequirementDiffs[i-1]
		curr := comp.RequirementDiffs[i]
		if prev.ID > curr.ID {
			t.Errorf("requirement diffs not sorted by ID: %s > %s", prev.ID, curr.ID)
		}
		if prev.ID == curr.ID {
			prevIdx := 0
			currIdx := 0
			if prev.SourceIndex != nil {
				prevIdx = *prev.SourceIndex
			}
			if curr.SourceIndex != nil {
				currIdx = *curr.SourceIndex
			}
			if prevIdx > currIdx {
				t.Errorf("same-ID diffs not sorted by sourceIndex: %d > %d for ID %s",
					prevIdx, currIdx, prev.ID)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 12. Baseline mode (golden/new roles)
// ---------------------------------------------------------------------------

func TestBaselineMode_SourceRoles(t *testing.T) {
	oldResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))
	newResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))

	opts := Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: types.ModeBaseline,
		MatchStrategy:  stratExactID,
	}

	comp := DiffHdf(oldResults, []hdf.HdfResults{newResults}, opts)

	if comp.ComparisonMode != types.ModeBaseline {
		t.Errorf("expected comparisonMode 'baseline', got %q", comp.ComparisonMode)
	}
	if len(comp.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(comp.Sources))
	}
	if comp.Sources[0].Role != types.RoleGolden {
		t.Errorf("expected first source role 'golden', got %q", comp.Sources[0].Role)
	}
	if comp.Sources[1].Role != types.RoleNew {
		t.Errorf("expected second source role 'new', got %q", comp.Sources[1].Role)
	}
}

// ---------------------------------------------------------------------------
// 13. MatchStrategy and matchConfidence
// ---------------------------------------------------------------------------

func TestMatchStrategyAndConfidence(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	if req.MatchStrategy != stratExactID {
		t.Errorf("expected matchStrategy %q, got %q", stratExactID, req.MatchStrategy)
	}
	if req.MatchConfidence == nil || *req.MatchConfidence != 1.0 {
		t.Errorf("expected matchConfidence 1.0, got %v", req.MatchConfidence)
	}
}

// ---------------------------------------------------------------------------
// 14. Top-level structure
// ---------------------------------------------------------------------------

func TestTopLevelStructure(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	if comp.FormatVersion != version100 {
		t.Errorf("expected formatVersion %q, got %q", version100, comp.FormatVersion)
	}
	if comp.ComparisonMode != types.ModeTemporal {
		t.Errorf("expected comparisonMode 'temporal', got %q", comp.ComparisonMode)
	}
	if comp.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if len(comp.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(comp.Sources))
	}
	if comp.Sources[0].Role != types.RoleOld {
		t.Errorf("expected first source role 'old', got %q", comp.Sources[0].Role)
	}
	if comp.Sources[1].Role != types.RoleNew {
		t.Errorf("expected second source role 'new', got %q", comp.Sources[1].Role)
	}
	if comp.Matching == nil {
		t.Error("expected matching config to be set")
	} else if comp.Matching.PrimaryStrategy != stratExactID {
		t.Errorf("expected primaryStrategy %q, got %q", stratExactID, comp.Matching.PrimaryStrategy)
	}
}

// ---------------------------------------------------------------------------
// 15. Field changes
// ---------------------------------------------------------------------------

func TestFieldChanges_ImpactReplace(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.3),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.0),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}

	found := false
	for _, fc := range req.FieldChanges {
		if fc.Path == fieldImpact && fc.Op == types.OpReplace {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected field change for %s with op 'replace', got %v", fieldImpact, req.FieldChanges)
	}
}

func TestFieldChanges_NoChangesForIdenticalReqs(t *testing.T) {
	req := makeRequirement("SV-001", hdf.Passed, 0.5)
	oldBaseline := makeBaseline("test-baseline", version100, req)
	newBaseline := makeBaseline("test-baseline", version100, req)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if len(r.FieldChanges) != 0 {
		t.Errorf("expected no field changes, got %v", r.FieldChanges)
	}
}

func TestFieldChanges_SeverityAdd(t *testing.T) {
	oldReq := makeRequirement("SV-001", hdf.Passed, 0.7)

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	sev := hdf.High
	newReq.Severity = &sev

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	opts := Options{
		TrackedFields:  []string{fieldSeverity},
		ComparisonMode: types.ModeTemporal,
		MatchStrategy:  stratExactID,
	}
	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, opts)

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if len(r.FieldChanges) != 1 {
		t.Fatalf("expected 1 field change, got %d: %v", len(r.FieldChanges), r.FieldChanges)
	}
	if r.FieldChanges[0].Op != types.OpAdd {
		t.Errorf("expected op 'add', got %q", r.FieldChanges[0].Op)
	}
	if r.FieldChanges[0].Path != fieldSeverity {
		t.Errorf("expected path %q, got %q", fieldSeverity, r.FieldChanges[0].Path)
	}
}

func TestFieldChanges_SeverityRemove(t *testing.T) {
	oldReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	sev := hdf.High
	oldReq.Severity = &sev

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	opts := Options{
		TrackedFields:  []string{fieldSeverity},
		ComparisonMode: types.ModeTemporal,
		MatchStrategy:  stratExactID,
	}
	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, opts)

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if len(r.FieldChanges) != 1 {
		t.Fatalf("expected 1 field change, got %d: %v", len(r.FieldChanges), r.FieldChanges)
	}
	if r.FieldChanges[0].Op != types.OpRemove {
		t.Errorf("expected op 'remove', got %q", r.FieldChanges[0].Op)
	}
	if r.FieldChanges[0].Path != fieldSeverity {
		t.Errorf("expected path %q, got %q", fieldSeverity, r.FieldChanges[0].Path)
	}
}

// ---------------------------------------------------------------------------
// 16. Empty baselines
// ---------------------------------------------------------------------------

func TestEmptyBaselines(t *testing.T) {
	oldResults := makeResults()
	newResults := makeResults()

	comp := DiffHdf(oldResults, []hdf.HdfResults{newResults}, defaultOpts())

	if len(comp.RequirementDiffs) != 0 {
		t.Errorf("expected 0 requirement diffs, got %d", len(comp.RequirementDiffs))
	}
	if len(comp.BaselineDiffs) != 0 {
		t.Errorf("expected 0 baseline diffs, got %d", len(comp.BaselineDiffs))
	}
	if comp.Summary.Total != 0 {
		t.Errorf("expected total=0, got %d", comp.Summary.Total)
	}
}

// ---------------------------------------------------------------------------
// 17. Title from before/after
// ---------------------------------------------------------------------------

func TestTitleFromNewReq(t *testing.T) {
	oldReq := makeRequirementWithTitle("SV-001", "Old Title", hdf.Passed, 0.7)
	newReq := makeRequirementWithTitle("SV-001", "New Title", hdf.Passed, 0.7)

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if r.Title != "New Title" {
		t.Errorf("expected title 'New Title', got %q", r.Title)
	}
}

func TestTitleFallbackToOldReq(t *testing.T) {
	oldReq := makeRequirementWithTitle("SV-001", "Old Title", hdf.Passed, 0.7)
	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if r.Title != "Old Title" {
		t.Errorf("expected title 'Old Title', got %q", r.Title)
	}
}

// ---------------------------------------------------------------------------
// 18. Change reasons for fixed/regressed include resultChanged
// ---------------------------------------------------------------------------

func TestChangeReasonsIncludeResultChanged(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirement("SV-002", hdf.Failed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	fixed := findReq(comp.RequirementDiffs, "SV-001")
	if fixed == nil {
		t.Fatal("SV-001 not found")
	}
	foundResult := false
	for _, r := range fixed.ChangeReasons {
		if r == types.ReasonResultChanged {
			foundResult = true
			break
		}
	}
	if !foundResult {
		t.Errorf("expected resultChanged in fixed req changeReasons, got %v", fixed.ChangeReasons)
	}

	regressed := findReq(comp.RequirementDiffs, "SV-002")
	if regressed == nil {
		t.Fatal("SV-002 not found")
	}
	foundResult = false
	for _, r := range regressed.ChangeReasons {
		if r == types.ReasonResultChanged {
			foundResult = true
			break
		}
	}
	if !foundResult {
		t.Errorf("expected resultChanged in regressed req changeReasons, got %v", regressed.ChangeReasons)
	}
}

// ---------------------------------------------------------------------------
// 19. Empty changeReasons for unchanged requirements
// ---------------------------------------------------------------------------

func TestEmptyChangeReasonsForUnchanged(t *testing.T) {
	req := makeRequirement("SV-001", hdf.Passed, 0.7)
	baseline := makeBaseline("test-baseline", version100, req)

	comp := DiffHdf(makeResults(baseline), []hdf.HdfResults{makeResults(baseline)}, defaultOpts())

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if len(r.ChangeReasons) != 0 {
		t.Errorf("expected empty changeReasons, got %v", r.ChangeReasons)
	}
}

// ---------------------------------------------------------------------------
// 20. Custom trackedFields
// ---------------------------------------------------------------------------

func TestCustomTrackedFields(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.3),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.0),
	)

	opts := Options{
		TrackedFields:  []string{fieldImpact},
		ComparisonMode: types.ModeTemporal,
		MatchStrategy:  stratExactID,
	}
	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, opts)

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if len(r.FieldChanges) != 1 {
		t.Fatalf("expected 1 field change, got %d", len(r.FieldChanges))
	}
	if r.FieldChanges[0].Path != fieldImpact {
		t.Errorf("expected field change path %q, got %q", fieldImpact, r.FieldChanges[0].Path)
	}
	if r.FieldChanges[0].Op != types.OpReplace {
		t.Errorf("expected op 'replace', got %q", r.FieldChanges[0].Op)
	}
}

// ---------------------------------------------------------------------------
// 21. Absent and new requirement change reasons are empty
// ---------------------------------------------------------------------------

func TestAbsentAndNewChangeReasonsEmpty(t *testing.T) {
	comp := buildAbsentAndNewComparison()
	assertAbsentAndNewSlicesEmpty(t, comp, true, false)
}

// ---------------------------------------------------------------------------
// 22. Absent and new requirement fieldChanges are empty
// ---------------------------------------------------------------------------

func TestAbsentAndNewFieldChangesEmpty(t *testing.T) {
	comp := buildAbsentAndNewComparison()
	assertAbsentAndNewSlicesEmpty(t, comp, false, true)
}

// ---------------------------------------------------------------------------
// 23. Baseline unchanged when same version
// ---------------------------------------------------------------------------

func TestBaselineUnchanged_SameVersion(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	if len(comp.BaselineDiffs) != 1 {
		t.Fatalf("expected 1 baseline diff, got %d", len(comp.BaselineDiffs))
	}
	if comp.BaselineDiffs[0].State != types.StateUnchanged {
		t.Errorf("expected state 'unchanged', got %q", comp.BaselineDiffs[0].State)
	}
}

// ---------------------------------------------------------------------------
// 24. Default options applied when fields are zero-value
// ---------------------------------------------------------------------------

func TestDefaultOptionsApplied(t *testing.T) {
	req := makeRequirement("SV-001", hdf.Passed, 0.7)
	baseline := makeBaseline("test-baseline", version100, req)
	results := makeResults(baseline)

	// Empty options -- should default to temporal mode, exactId strategy, default tracked fields
	comp := DiffHdf(results, []hdf.HdfResults{results}, Options{})

	if comp.ComparisonMode != types.ModeTemporal {
		t.Errorf("expected default comparisonMode 'temporal', got %q", comp.ComparisonMode)
	}
	if comp.Matching == nil || comp.Matching.PrimaryStrategy != stratExactID {
		t.Errorf("expected default primaryStrategy %q", stratExactID)
	}
}

// ---------------------------------------------------------------------------
// 25. Tags field change tracking
// ---------------------------------------------------------------------------

func TestFieldChanges_TagsReplace(t *testing.T) {
	oldReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	oldReq.Tags = map[string]interface{}{"cci": []interface{}{"CCI-000001"}}

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	newReq.Tags = map[string]interface{}{"cci": []interface{}{"CCI-000002"}}

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	comp := DiffHdf(makeResults(oldBaseline), []hdf.HdfResults{makeResults(newBaseline)}, defaultOpts())

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}

	found := false
	for _, fc := range r.FieldChanges {
		if fc.Path == "tags" && fc.Op == types.OpReplace {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected field change for tags with op 'replace', got %v", r.FieldChanges)
	}
}
