package diff

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go"
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
	titlePrevious = "Previous Title"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func strPtr(s string) *string { return &s }

func makeRequirement(id string, status hdf.ResultStatus, impact float64) hdf.EvaluatedRequirement {
	return testhdf.Req(id,
		testhdf.Impact(impact),
		testhdf.Status(status),
		testhdf.Desc("test"),
		testhdf.CodeDesc("test"),
		testhdf.StartTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
	)
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
		Integrity:    &hdf.Integrity{},
		Depends:      []hdf.Dependency{},
	}
}

func makeResults(baselines ...hdf.EvaluatedBaseline) hdf.HDFResults {
	return hdf.HDFResults{Baselines: baselines}
}

func findReq(diffs []RequirementDiff, id string) *RequirementDiff {
	for i := range diffs {
		if diffs[i].ID == id {
			return &diffs[i]
		}
	}
	return nil
}

func findBaselineDiff(diffs []BaselineDiff, name string) *BaselineDiff {
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
		ComparisonMode: ModeTemporal,
		MatchStrategy:  stratExactID,
	}
}

// mustDiffHdf calls DiffHdf and fails the test if it returns an error.
func mustDiffHdf(t *testing.T, oldResults hdf.HDFResults, newResults []hdf.HDFResults, opts Options) HdfComparison {
	t.Helper()
	comp, err := DiffHdf(context.Background(), oldResults, newResults, opts)
	if err != nil {
		t.Fatalf("DiffHdf returned unexpected error: %v", err)
	}
	return comp
}

// TestDiffHdf_HonorsCancellation proves DiffHdf returns context.Canceled from a
// pre-cancelled context instead of running the comparison.
func TestDiffHdf_HonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	doc := makeResults(makeBaseline("b", "1.0.0"))
	_, err := DiffHdf(ctx, doc, []hdf.HDFResults{doc}, defaultOpts())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// assertAbsentAndNewSlicesEmpty validates that both changeReasons and fieldChanges
// are empty for absent and new requirements. Shared helper eliminates duplication.
func assertAbsentAndNewSlicesEmpty(
	t *testing.T,
	comp HdfComparison,
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

func buildAbsentAndNewComparison(t *testing.T) HdfComparison {
	t.Helper()
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-002", hdf.Passed, 0.7),
	)
	return mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())
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

	comp := mustDiffHdf(t, results, []hdf.HDFResults{results}, defaultOpts())

	for _, req := range comp.RequirementDiffs {
		if req.State != StateUnchanged {
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

	comp := mustDiffHdf(t, results, []hdf.HDFResults{results}, defaultOpts())

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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found in diffs")
	}
	if req.State != StateFixed {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found in diffs")
	}
	if req.State != StateRegressed {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-002")
	if req == nil {
		t.Fatal("SV-002 not found in diffs")
	}
	if req.State != StateNew {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-002")
	if req == nil {
		t.Fatal("SV-002 not found in diffs")
	}
	if req.State != StateAbsent {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found in diffs")
	}
	// Impact changed from 0.3 (passed) to 0.0 (notApplicable) -> "updated" state
	if req.State != StateUpdated {
		t.Errorf("expected state 'updated', got %q", req.State)
	}

	foundImpactChanged := false
	for _, reason := range req.ChangeReasons {
		if reason == ReasonImpactChanged {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	if len(comp.BaselineDiffs) != 1 {
		t.Fatalf("expected 1 baseline diff, got %d", len(comp.BaselineDiffs))
	}

	bd := comp.BaselineDiffs[0]
	if bd.Name != "rhel9-stig-baseline" {
		t.Errorf("expected name 'rhel9-stig-baseline', got %q", bd.Name)
	}
	if bd.State != StateUpdated {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	if len(comp.BaselineDiffs) != 2 {
		t.Fatalf("expected 2 baseline diffs, got %d", len(comp.BaselineDiffs))
	}

	alpha := findBaselineDiff(comp.BaselineDiffs, "baseline-alpha")
	if alpha == nil {
		t.Fatal("baseline-alpha not found")
	}
	if alpha.State != StateAbsent {
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
	if beta.State != StateNew {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

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
	oldReq.Tags = map[string]any{"cci": []any{"CCI-000001"}}

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	newReq.Tags = map[string]any{"cci": []any{"CCI-000002"}}

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	// The requirement should be "unchanged" in status but have changeReasons
	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	if req.State != StateUnchanged {
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
	if driftReq.State != StateUnchanged {
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
		ComparisonMode: ModeFleet,
		MatchStrategy:  stratExactID,
	}

	comp := mustDiffHdf(t, reference, []hdf.HDFResults{system1, system2}, opts)

	if comp.ComparisonMode != ModeFleet {
		t.Errorf("expected comparisonMode 'fleet', got %q", comp.ComparisonMode)
	}

	// Sources: reference + 2 systems = 3
	if len(comp.Sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(comp.Sources))
	}
	if comp.Sources[0].Role != RoleReference {
		t.Errorf("expected first source role 'reference', got %q", comp.Sources[0].Role)
	}
	if comp.Sources[1].Role != RoleSystem {
		t.Errorf("expected second source role 'system', got %q", comp.Sources[1].Role)
	}
	if comp.Sources[2].Role != RoleSystem {
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
			if rd.State != StateRegressed {
				t.Errorf("expected SV-001 in system1 to be regressed, got %q", rd.State)
			}
		}
		if rd.ID == "SV-001" && rd.SourceIndex != nil && *rd.SourceIndex == 2 {
			if rd.State != StateUnchanged {
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
		ComparisonMode: ModeFleet,
		MatchStrategy:  stratExactID,
	}

	comp := mustDiffHdf(t, reference, []hdf.HDFResults{system1, system2}, opts)

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
		ComparisonMode: ModeBaseline,
		MatchStrategy:  stratExactID,
	}

	comp := mustDiffHdf(t, oldResults, []hdf.HDFResults{newResults}, opts)

	if comp.ComparisonMode != ModeBaseline {
		t.Errorf("expected comparisonMode 'baseline', got %q", comp.ComparisonMode)
	}
	if len(comp.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(comp.Sources))
	}
	if comp.Sources[0].Role != RoleGolden {
		t.Errorf("expected first source role 'golden', got %q", comp.Sources[0].Role)
	}
	if comp.Sources[1].Role != RoleNew {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	if comp.FormatVersion != version100 {
		t.Errorf("expected formatVersion %q, got %q", version100, comp.FormatVersion)
	}
	if comp.ComparisonMode != ModeTemporal {
		t.Errorf("expected comparisonMode 'temporal', got %q", comp.ComparisonMode)
	}
	if comp.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if len(comp.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(comp.Sources))
	}
	if comp.Sources[0].Role != RoleOld {
		t.Errorf("expected first source role 'old', got %q", comp.Sources[0].Role)
	}
	if comp.Sources[1].Role != RoleNew {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	req := findReq(comp.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}

	found := false
	for _, fc := range req.FieldChanges {
		if fc.Path == fieldImpact && fc.Op == OpReplace {
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

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
	sev := hdf.SeverityHigh
	newReq.Severity = &sev

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	opts := Options{
		TrackedFields:  []string{fieldSeverity},
		ComparisonMode: ModeTemporal,
		MatchStrategy:  stratExactID,
	}
	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, opts)

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if len(r.FieldChanges) != 1 {
		t.Fatalf("expected 1 field change, got %d: %v", len(r.FieldChanges), r.FieldChanges)
	}
	if r.FieldChanges[0].Op != OpAdd {
		t.Errorf("expected op 'add', got %q", r.FieldChanges[0].Op)
	}
	if r.FieldChanges[0].Path != fieldSeverity {
		t.Errorf("expected path %q, got %q", fieldSeverity, r.FieldChanges[0].Path)
	}
}

func TestFieldChanges_SeverityRemove(t *testing.T) {
	oldReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	sev := hdf.SeverityHigh
	oldReq.Severity = &sev

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	opts := Options{
		TrackedFields:  []string{fieldSeverity},
		ComparisonMode: ModeTemporal,
		MatchStrategy:  stratExactID,
	}
	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, opts)

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if len(r.FieldChanges) != 1 {
		t.Fatalf("expected 1 field change, got %d: %v", len(r.FieldChanges), r.FieldChanges)
	}
	if r.FieldChanges[0].Op != OpRemove {
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

	comp := mustDiffHdf(t, oldResults, []hdf.HDFResults{newResults}, defaultOpts())

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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	fixed := findReq(comp.RequirementDiffs, "SV-001")
	if fixed == nil {
		t.Fatal("SV-001 not found")
	}
	foundResult := false
	for _, r := range fixed.ChangeReasons {
		if r == ReasonResultChanged {
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
		if r == ReasonResultChanged {
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

	comp := mustDiffHdf(t, makeResults(baseline), []hdf.HDFResults{makeResults(baseline)}, defaultOpts())

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
		ComparisonMode: ModeTemporal,
		MatchStrategy:  stratExactID,
	}
	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, opts)

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
	if r.FieldChanges[0].Op != OpReplace {
		t.Errorf("expected op 'replace', got %q", r.FieldChanges[0].Op)
	}
}

// ---------------------------------------------------------------------------
// 21. Absent and new requirement change reasons are empty
// ---------------------------------------------------------------------------

func TestAbsentAndNewChangeReasonsEmpty(t *testing.T) {
	comp := buildAbsentAndNewComparison(t)
	assertAbsentAndNewSlicesEmpty(t, comp, true, false)
}

// ---------------------------------------------------------------------------
// 22. Absent and new requirement fieldChanges are empty
// ---------------------------------------------------------------------------

func TestAbsentAndNewFieldChangesEmpty(t *testing.T) {
	comp := buildAbsentAndNewComparison(t)
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

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	if len(comp.BaselineDiffs) != 1 {
		t.Fatalf("expected 1 baseline diff, got %d", len(comp.BaselineDiffs))
	}
	if comp.BaselineDiffs[0].State != StateUnchanged {
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
	comp := mustDiffHdf(t, results, []hdf.HDFResults{results}, Options{})

	if comp.ComparisonMode != ModeTemporal {
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
	oldReq.Tags = map[string]any{"cci": []any{"CCI-000001"}}

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	newReq.Tags = map[string]any{"cci": []any{"CCI-000002"}}

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}

	found := false
	for _, fc := range r.FieldChanges {
		if fc.Path == "tags" && fc.Op == OpReplace {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected field change for tags with op 'replace', got %v", r.FieldChanges)
	}
}

// ---------------------------------------------------------------------------
// Coverage: buildSources — multiSource and default branches
// ---------------------------------------------------------------------------

func TestBuildSources_MultiSource(t *testing.T) {
	sources := buildSources(ModeMultiSource)
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}
	if sources[0].Role != RoleOld {
		t.Errorf("expected role 'old', got %q", sources[0].Role)
	}
	if sources[1].Role != RoleNew {
		t.Errorf("expected role 'new', got %q", sources[1].Role)
	}
}

func TestBuildSources_DefaultMode(t *testing.T) {
	sources := buildSources("unknownMode")
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources for default branch, got %d", len(sources))
	}
	if sources[0].Role != RoleOld {
		t.Errorf("expected role 'old', got %q", sources[0].Role)
	}
}

func TestBuildSources_FleetMode(t *testing.T) {
	sources := buildSources(ModeFleet)
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources for fleet, got %d", len(sources))
	}
}

// ---------------------------------------------------------------------------
// Coverage: getFieldValue — all branches
// ---------------------------------------------------------------------------

func TestGetFieldValue_AllBranches(t *testing.T) {
	sev := hdf.SeverityHigh
	title := "My Title"
	req := hdf.EvaluatedRequirement{
		Impact:       0.7,
		Severity:     &sev,
		Tags:         map[string]any{"cci": "CCI-001"},
		Title:        &title,
		Descriptions: []hdf.Description{{Label: "default", Data: "desc"}},
	}

	tests := []struct {
		field    string
		wantNil  bool
		wantType string
	}{
		{fieldNameImpact, false, "float64"},
		{fieldNameSeverity, false, "string"},
		{fieldNameTags, false, "map"},
		{fieldNameTitle, false, "string"},
		{fieldNameDescriptions, false, "slice"},
		{"unknown_field", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			val := getFieldValue(req, tc.field)
			if tc.wantNil {
				if val != nil {
					t.Errorf("expected nil for field %q, got %v", tc.field, val)
				}
			} else {
				if val == nil {
					t.Errorf("expected non-nil for field %q", tc.field)
				}
			}
		})
	}
}

func TestGetFieldValue_NilSeverity(t *testing.T) {
	req := hdf.EvaluatedRequirement{Severity: nil}
	val := getFieldValue(req, fieldNameSeverity)
	if val != nil {
		t.Errorf("expected nil for nil severity, got %v", val)
	}
}

func TestGetFieldValue_NilTitle(t *testing.T) {
	req := hdf.EvaluatedRequirement{Title: nil}
	val := getFieldValue(req, fieldNameTitle)
	if val != nil {
		t.Errorf("expected nil for nil title, got %v", val)
	}
}

// ---------------------------------------------------------------------------
// Coverage: isZeroValue — all branches
// ---------------------------------------------------------------------------

func TestIsZeroValue_TableDriven(t *testing.T) {
	var nilMap map[string]any
	var nilSlice []string
	var nilPtr *string
	testStr := "test-value"

	tests := []struct {
		name     string
		value    any
		expected bool
	}{
		{"nil interface", nil, true},
		{"nil pointer", nilPtr, true},
		{"non-nil pointer", &testStr, false},
		{"nil map", nilMap, true},
		{"non-nil empty map", map[string]any{}, false},
		{"nil slice", nilSlice, true},
		{"non-nil empty slice", []string{}, false},
		{"zero int", 0, false},
		{"zero float", 0.0, false},
		{"non-zero float", 0.7, false},
		{"empty string", "", false},
		{"non-empty string", "hello", false},
		{"bool false", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isZeroValue(tc.value)
			if got != tc.expected {
				t.Errorf("isZeroValue(%v) = %v, want %v", tc.value, got, tc.expected)
			}
		})
	}
}

// jsonMarshal was removed in favor of reflect.DeepEqual for comparison.
// See TestFieldChanges_KeyOrderIndependentMaps for verification.

// ---------------------------------------------------------------------------
// Coverage: derefStr — both branches
// ---------------------------------------------------------------------------

func TestDerefStr_Nil(t *testing.T) {
	result := derefStr(nil)
	if result != "" {
		t.Errorf("expected empty string for nil, got %q", result)
	}
}

func TestDerefStr_NonNil(t *testing.T) {
	s := "hello"
	result := derefStr(&s)
	if result != "hello" {
		t.Errorf("expected \"hello\", got %q", result)
	}
}

func TestDerefStr_EmptyString(t *testing.T) {
	s := ""
	result := derefStr(&s)
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// Coverage: resolveTitle — both nil, only old set
// ---------------------------------------------------------------------------

func TestResolveTitle_BothNil(t *testing.T) {
	result := resolveTitle(nil, nil)
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestResolveTitle_OnlyOldSet(t *testing.T) {
	oldTitle := titlePrevious
	result := resolveTitle(&oldTitle, nil)
	if result != titlePrevious {
		t.Errorf("expected %q, got %q", titlePrevious, result)
	}
}

func TestResolveTitle_BothSet(t *testing.T) {
	oldTitle := titlePrevious
	newTitle := "Current Title"
	result := resolveTitle(&oldTitle, &newTitle)
	if result != "Current Title" {
		t.Errorf("expected \"Current Title\", got %q", result)
	}
}

// ---------------------------------------------------------------------------
// Coverage: DiffHdf — empty newResults slice
// ---------------------------------------------------------------------------

func TestDiffHdf_EmptyNewResults(t *testing.T) {
	baseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	// Empty newResults slice — should not panic
	comp := mustDiffHdf(t, makeResults(baseline), []hdf.HDFResults{}, defaultOpts())

	// All old requirements should be absent
	if len(comp.RequirementDiffs) != 1 {
		t.Fatalf("expected 1 requirement diff, got %d", len(comp.RequirementDiffs))
	}
	if comp.RequirementDiffs[0].State != StateAbsent {
		t.Errorf("expected state 'absent', got %q", comp.RequirementDiffs[0].State)
	}
}

// ---------------------------------------------------------------------------
// Coverage: computeFieldChanges — descriptions tracked field change
// ---------------------------------------------------------------------------

func TestFieldChanges_DescriptionsTracked(t *testing.T) {
	oldReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	oldReq.Descriptions = []hdf.Description{{Label: "default", Data: "old desc"}}

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	newReq.Descriptions = []hdf.Description{{Label: "default", Data: "new desc"}}

	changes := computeFieldChanges(oldReq, newReq, []string{fieldNameDescriptions})
	if len(changes) != 1 {
		t.Fatalf("expected 1 field change, got %d", len(changes))
	}
	if changes[0].Path != fieldNameDescriptions {
		t.Errorf("expected path %q, got %q", fieldNameDescriptions, changes[0].Path)
	}
	if changes[0].Op != OpReplace {
		t.Errorf("expected op 'replace', got %q", changes[0].Op)
	}
}

// ---------------------------------------------------------------------------
// Coverage: multiSource mode
// ---------------------------------------------------------------------------

func TestMultiSourceMode_SourceRoles(t *testing.T) {
	oldResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))
	newResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))

	opts := Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: ModeMultiSource,
		MatchStrategy:  stratExactID,
	}

	comp := mustDiffHdf(t, oldResults, []hdf.HDFResults{newResults}, opts)

	if comp.ComparisonMode != ModeMultiSource {
		t.Errorf("expected comparisonMode 'multiSource', got %q", comp.ComparisonMode)
	}
	if len(comp.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(comp.Sources))
	}
	if comp.Sources[0].Role != RoleOld {
		t.Errorf("expected first source role 'old', got %q", comp.Sources[0].Role)
	}
}

// ---------------------------------------------------------------------------
// C1: DiffHdf returns error for invalid strategy (not panic)
// ---------------------------------------------------------------------------

func TestDiffHdf_InvalidStrategy(t *testing.T) {
	oldResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))
	newResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))

	opts := Options{
		TrackedFields:  []string{fieldImpact},
		ComparisonMode: ModeTemporal,
		MatchStrategy:  "nonexistentStrategy",
	}

	_, err := DiffHdf(context.Background(), oldResults, []hdf.HDFResults{newResults}, opts)
	if err == nil {
		t.Fatal("expected error for invalid strategy, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistentStrategy") {
		t.Errorf("expected error message to contain strategy name, got: %s", err.Error())
	}
}

func TestDiffHdf_InvalidFallbackStrategy(t *testing.T) {
	oldResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))
	newResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))

	opts := Options{
		TrackedFields:      []string{fieldImpact},
		ComparisonMode:     ModeTemporal,
		MatchStrategy:      stratExactID,
		FallbackStrategies: []string{"badFallback"},
	}

	_, err := DiffHdf(context.Background(), oldResults, []hdf.HDFResults{newResults}, opts)
	if err == nil {
		t.Fatal("expected error for invalid fallback strategy, got nil")
	}
}

func TestDiffHdf_ValidStrategy_NoError(t *testing.T) {
	oldResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))
	newResults := makeResults(makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))

	comp, err := DiffHdf(context.Background(), oldResults, []hdf.HDFResults{newResults}, defaultOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comp.FormatVersion != version100 {
		t.Errorf("expected formatVersion %q, got %q", version100, comp.FormatVersion)
	}
}

// ---------------------------------------------------------------------------
// C2: Key-order-independent object comparison
// ---------------------------------------------------------------------------

func TestFieldChanges_KeyOrderIndependentMaps(t *testing.T) {
	// Two maps with the same keys but created in different order.
	// JSON marshalling could produce different strings but reflect.DeepEqual
	// should consider them equal.
	oldReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	oldReq.Tags = map[string]any{"b": "two", "a": "one"}

	newReq := makeRequirement("SV-001", hdf.Passed, 0.7)
	newReq.Tags = map[string]any{"a": "one", "b": "two"}

	oldBaseline := makeBaseline("test-baseline", version100, oldReq)
	newBaseline := makeBaseline("test-baseline", version100, newReq)

	opts := Options{
		TrackedFields:  []string{"tags"},
		ComparisonMode: ModeTemporal,
		MatchStrategy:  stratExactID,
	}
	comp, err := DiffHdf(context.Background(), makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := findReq(comp.RequirementDiffs, "SV-001")
	if r == nil {
		t.Fatal("SV-001 not found")
	}
	if len(r.FieldChanges) != 0 {
		t.Errorf("expected 0 field changes (maps are equal regardless of key order), got %d: %v",
			len(r.FieldChanges), r.FieldChanges)
	}
}

// ---------------------------------------------------------------------------
// Baseline field on RequirementDiff
// ---------------------------------------------------------------------------

func TestRequirementDiff_BaselineField_SingleBaseline(t *testing.T) {
	baseline := makeBaseline("rhel9-stig", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
	)
	oldResults := makeResults(baseline)
	newResults := makeResults(baseline)

	comp := mustDiffHdf(t, oldResults, []hdf.HDFResults{newResults}, defaultOpts())

	for _, req := range comp.RequirementDiffs {
		if req.Baseline != "rhel9-stig" {
			t.Errorf("requirement %s: expected baseline 'rhel9-stig', got %q", req.ID, req.Baseline)
		}
	}
}

func TestRequirementDiff_BaselineField_MultipleBaselines(t *testing.T) {
	baselineA := makeBaseline("rhel9-stig", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
	)
	baselineB := makeBaseline("windows-stig", version100,
		makeRequirement("WIN-001", hdf.Passed, 0.5),
	)
	oldResults := makeResults(baselineA, baselineB)
	newResults := makeResults(baselineA, baselineB)

	comp := mustDiffHdf(t, oldResults, []hdf.HDFResults{newResults}, defaultOpts())

	sv001 := findReq(comp.RequirementDiffs, "SV-001")
	if sv001 == nil {
		t.Fatal("SV-001 not found")
	}
	if sv001.Baseline != "rhel9-stig" {
		t.Errorf("SV-001: expected baseline 'rhel9-stig', got %q", sv001.Baseline)
	}

	win001 := findReq(comp.RequirementDiffs, "WIN-001")
	if win001 == nil {
		t.Fatal("WIN-001 not found")
	}
	if win001.Baseline != "windows-stig" {
		t.Errorf("WIN-001: expected baseline 'windows-stig', got %q", win001.Baseline)
	}
}

func TestRequirementDiff_BaselineField_NewRequirement(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
	)

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	newReq := findReq(comp.RequirementDiffs, "SV-002")
	if newReq == nil {
		t.Fatal("SV-002 not found")
	}
	if newReq.Baseline != "test-baseline" {
		t.Errorf("SV-002: expected baseline 'test-baseline', got %q", newReq.Baseline)
	}
}

func TestRequirementDiff_BaselineField_AbsentRequirement(t *testing.T) {
	oldBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
		makeRequirement("SV-002", hdf.Passed, 0.5),
	)
	newBaseline := makeBaseline("test-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)

	comp := mustDiffHdf(t, makeResults(oldBaseline), []hdf.HDFResults{makeResults(newBaseline)}, defaultOpts())

	absent := findReq(comp.RequirementDiffs, "SV-002")
	if absent == nil {
		t.Fatal("SV-002 not found")
	}
	if absent.Baseline != "test-baseline" {
		t.Errorf("SV-002: expected baseline 'test-baseline', got %q", absent.Baseline)
	}
}

func TestRequirementDiff_BaselineField_FleetMode(t *testing.T) {
	reference := makeResults(makeBaseline("stig-baseline", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	))
	system1 := makeResults(makeBaseline("stig-baseline", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
	))

	opts := Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: ModeFleet,
		MatchStrategy:  stratExactID,
	}

	comp := mustDiffHdf(t, reference, []hdf.HDFResults{system1}, opts)

	sv001 := findReq(comp.RequirementDiffs, "SV-001")
	if sv001 == nil {
		t.Fatal("SV-001 not found")
	}
	if sv001.Baseline != "stig-baseline" {
		t.Errorf("SV-001: expected baseline 'stig-baseline', got %q", sv001.Baseline)
	}
}

func TestRequirementDiff_BaselineField_DuplicateIDsAcrossBaselines(t *testing.T) {
	// Same requirement ID in two baselines → Baseline should be "(multiple)"
	baselineA := makeBaseline("rhel9-stig", version100,
		makeRequirement("SV-001", hdf.Failed, 0.7),
	)
	baselineB := makeBaseline("container-stig", version100,
		makeRequirement("SV-001", hdf.Passed, 0.7),
	)
	oldResults := makeResults(baselineA, baselineB)
	newResults := makeResults(baselineA, baselineB)

	comp := mustDiffHdf(t, oldResults, []hdf.HDFResults{newResults}, defaultOpts())

	sv001 := findReq(comp.RequirementDiffs, "SV-001")
	if sv001 == nil {
		t.Fatal("SV-001 not found")
	}
	if sv001.Baseline != baselineMultiple {
		t.Errorf("SV-001: expected baseline %q for duplicate ID, got %q", baselineMultiple, sv001.Baseline)
	}
}
