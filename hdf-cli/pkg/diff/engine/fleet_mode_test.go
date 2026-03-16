package engine

import (
	"fmt"
	"sort"
	"testing"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// ---------------------------------------------------------------------------
// Fleet mode test helpers
// ---------------------------------------------------------------------------

// findReqsBySource returns all requirement diffs with the given sourceIndex.
func findReqsBySource(diffs []types.RequirementDiff, sourceIndex int) []types.RequirementDiff {
	var result []types.RequirementDiff
	for _, r := range diffs {
		if r.SourceIndex != nil && *r.SourceIndex == sourceIndex {
			result = append(result, r)
		}
	}
	return result
}

// findReqByIDAndSource returns the first requirement diff matching both id and sourceIndex.
func findReqByIDAndSource(diffs []types.RequirementDiff, id string, sourceIndex int) *types.RequirementDiff {
	for i := range diffs {
		if diffs[i].ID == id && diffs[i].SourceIndex != nil && *diffs[i].SourceIndex == sourceIndex {
			return &diffs[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Fleet mode test fixtures
// ---------------------------------------------------------------------------

func buildFleetReference() hdf.HdfResults {
	return makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Passed, 0.5),
	))
}

func buildFleetSystemA() hdf.HdfResults {
	return makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Failed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Passed, 0.5),
	))
}

func buildFleetSystemB() hdf.HdfResults {
	return makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Passed, 0.5),
	))
}

func fleetOpts() Options {
	return Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: types.ModeFleet,
		MatchStrategy:  stratExactID,
	}
}

// ---------------------------------------------------------------------------
// 1. Top-level metadata
// ---------------------------------------------------------------------------

func TestFleet_ComparisonModeIsFleet(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.ComparisonMode != types.ModeFleet {
		t.Errorf("expected comparisonMode 'fleet', got %q", diff.ComparisonMode)
	}
}

func TestFleet_FormatVersion(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.FormatVersion != version100 {
		t.Errorf("expected formatVersion %q, got %q", version100, diff.FormatVersion)
	}
}

// ---------------------------------------------------------------------------
// 2. Sources array
// ---------------------------------------------------------------------------

func TestFleet_ThreeSourcesForRefPlusTwoSystems(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if len(diff.Sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(diff.Sources))
	}
}

func TestFleet_FirstSourceRoleIsReference(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.Sources[0].Role != types.RoleReference {
		t.Errorf("expected first source role 'reference', got %q", diff.Sources[0].Role)
	}
}

func TestFleet_FirstSourceLabelIsReference(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.Sources[0].Label != "Reference" {
		t.Errorf("expected first source label 'Reference', got %q", diff.Sources[0].Label)
	}
}

func TestFleet_SystemSourceRolesAreSystem(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.Sources[1].Role != types.RoleSystem {
		t.Errorf("expected second source role 'system', got %q", diff.Sources[1].Role)
	}
	if diff.Sources[2].Role != types.RoleSystem {
		t.Errorf("expected third source role 'system', got %q", diff.Sources[2].Role)
	}
}

func TestFleet_SystemSourceLabelsSequentiallyNumbered(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.Sources[1].Label != "System 1" {
		t.Errorf("expected second source label 'System 1', got %q", diff.Sources[1].Label)
	}
	if diff.Sources[2].Label != "System 2" {
		t.Errorf("expected third source label 'System 2', got %q", diff.Sources[2].Label)
	}
}

// ---------------------------------------------------------------------------
// 3. RequirementDiffs with sourceIndex
// ---------------------------------------------------------------------------

func TestFleet_IncludesDiffsForAllSystems(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	// 2 requirements x 2 systems = 4 diffs
	if len(diff.RequirementDiffs) != 4 {
		t.Errorf("expected 4 requirement diffs, got %d", len(diff.RequirementDiffs))
	}
}

func TestFleet_SourceIndex1ForSystemA(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	sysADiffs := findReqsBySource(diff.RequirementDiffs, 1)
	if len(sysADiffs) != 2 {
		t.Errorf("expected 2 diffs for sourceIndex=1, got %d", len(sysADiffs))
	}
}

func TestFleet_SourceIndex2ForSystemB(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	sysBDiffs := findReqsBySource(diff.RequirementDiffs, 2)
	if len(sysBDiffs) != 2 {
		t.Errorf("expected 2 diffs for sourceIndex=2, got %d", len(sysBDiffs))
	}
}

func TestFleet_SV001RegressedInSystemA(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	sv001 := findReqByIDAndSource(diff.RequirementDiffs, "SV-001", 1)
	if sv001 == nil {
		t.Fatal("SV-001 with sourceIndex=1 not found")
	}
	if sv001.State != types.StateRegressed {
		t.Errorf("expected SV-001 in system-A state 'regressed', got %q", sv001.State)
	}
	if sv001.OldEffectiveStatus != statusPassed {
		t.Errorf("expected oldEffectiveStatus 'passed', got %q", sv001.OldEffectiveStatus)
	}
	if sv001.NewEffectiveStatus != statusFailed {
		t.Errorf("expected newEffectiveStatus 'failed', got %q", sv001.NewEffectiveStatus)
	}
}

func TestFleet_SV002UnchangedInSystemA(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	sv002 := findReqByIDAndSource(diff.RequirementDiffs, "SV-002", 1)
	if sv002 == nil {
		t.Fatal("SV-002 with sourceIndex=1 not found")
	}
	if sv002.State != types.StateUnchanged {
		t.Errorf("expected SV-002 in system-A state 'unchanged', got %q", sv002.State)
	}
}

func TestFleet_AllUnchangedInSystemB(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	sysBDiffs := findReqsBySource(diff.RequirementDiffs, 2)
	for _, req := range sysBDiffs {
		if req.State != types.StateUnchanged {
			t.Errorf("expected state 'unchanged' for %s in system-B, got %q", req.ID, req.State)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Summary counts
// ---------------------------------------------------------------------------

func TestFleet_SummaryTotalAcrossAllSystems(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	// 2 requirements x 2 systems = 4 total
	if diff.Summary.Total != 4 {
		t.Errorf("expected total=4, got %d", diff.Summary.Total)
	}
}

func TestFleet_SummaryStateCounts(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.Summary.Regressed != 1 {
		t.Errorf("expected regressed=1, got %d", diff.Summary.Regressed)
	}
	if diff.Summary.Unchanged != 3 {
		t.Errorf("expected unchanged=3, got %d", diff.Summary.Unchanged)
	}
	if diff.Summary.Fixed != 0 {
		t.Errorf("expected fixed=0, got %d", diff.Summary.Fixed)
	}
	if diff.Summary.New != 0 {
		t.Errorf("expected new=0, got %d", diff.Summary.New)
	}
	if diff.Summary.Absent != 0 {
		t.Errorf("expected absent=0, got %d", diff.Summary.Absent)
	}
}

func TestFleet_SummaryMatchedCounts(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.Summary.MatchedCount != 4 {
		t.Errorf("expected matchedCount=4, got %d", diff.Summary.MatchedCount)
	}
	if diff.Summary.UnmatchedOldCount != 0 {
		t.Errorf("expected unmatchedOldCount=0, got %d", diff.Summary.UnmatchedOldCount)
	}
	if diff.Summary.UnmatchedNewCount != 0 {
		t.Errorf("expected unmatchedNewCount=0, got %d", diff.Summary.UnmatchedNewCount)
	}
}

// ---------------------------------------------------------------------------
// 5. Single system fleet mode
// ---------------------------------------------------------------------------

func TestFleet_SingleSystemArray(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA()}, fleetOpts())

	if len(diff.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(diff.Sources))
	}
	if diff.Sources[0].Role != types.RoleReference {
		t.Errorf("expected first source role 'reference', got %q", diff.Sources[0].Role)
	}
	if diff.Sources[1].Role != types.RoleSystem {
		t.Errorf("expected second source role 'system', got %q", diff.Sources[1].Role)
	}
	if diff.Sources[1].Label != "System 1" {
		t.Errorf("expected second source label 'System 1', got %q", diff.Sources[1].Label)
	}
}

func TestFleet_SingleSystemSourceIndex(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA()}, fleetOpts())

	if len(diff.RequirementDiffs) != 2 {
		t.Errorf("expected 2 requirement diffs, got %d", len(diff.RequirementDiffs))
	}
	for _, req := range diff.RequirementDiffs {
		if req.SourceIndex == nil || *req.SourceIndex != 1 {
			idx := -1
			if req.SourceIndex != nil {
				idx = *req.SourceIndex
			}
			t.Errorf("expected sourceIndex=1 for %s, got %d", req.ID, idx)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. Requirement ordering
// ---------------------------------------------------------------------------

func TestFleet_RequirementsSortedByIDThenSourceIndex(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	keys := make([]string, len(diff.RequirementDiffs))
	for i, r := range diff.RequirementDiffs {
		idx := 0
		if r.SourceIndex != nil {
			idx = *r.SourceIndex
		}
		keys[i] = fmt.Sprintf("%s:%d", r.ID, idx)
	}

	sorted := make([]string, len(keys))
	copy(sorted, keys)
	sort.Strings(sorted)

	for i := range keys {
		if keys[i] != sorted[i] {
			t.Errorf("requirementDiffs not sorted by id:sourceIndex: got %v, want %v", keys, sorted)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// 7. Fleet with system that has extra requirements
// ---------------------------------------------------------------------------

func TestFleet_ExtraRequirementMarkedAsNew(t *testing.T) {
	systemWithExtra := makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Passed, 0.5),
		makeRequirementWithTitle("SV-003", "Check C", hdf.Failed, 0.9),
	))

	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{systemWithExtra}, fleetOpts())

	sysReqs := findReqsBySource(diff.RequirementDiffs, 1)
	sv003 := findReq(sysReqs, "SV-003")
	if sv003 == nil {
		t.Fatal("SV-003 not found in system diffs")
	}
	if sv003.State != types.StateNew {
		t.Errorf("expected SV-003 state 'new', got %q", sv003.State)
	}
}

func TestFleet_ExtraRequirementInSummaryCounts(t *testing.T) {
	systemWithExtra := makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Passed, 0.5),
		makeRequirementWithTitle("SV-003", "Check C", hdf.Failed, 0.9),
	))

	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{systemWithExtra}, fleetOpts())

	if diff.Summary.New != 1 {
		t.Errorf("expected new=1, got %d", diff.Summary.New)
	}
	if diff.Summary.Unchanged != 2 {
		t.Errorf("expected unchanged=2, got %d", diff.Summary.Unchanged)
	}
	if diff.Summary.Total != 3 {
		t.Errorf("expected total=3, got %d", diff.Summary.Total)
	}
}

// ---------------------------------------------------------------------------
// 8. System missing a reference requirement
// ---------------------------------------------------------------------------

func TestFleet_MissingRequirementMarkedAsAbsent(t *testing.T) {
	systemMissing := makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		// SV-002 intentionally absent
	))

	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{systemMissing}, fleetOpts())

	sysReqs := findReqsBySource(diff.RequirementDiffs, 1)
	sv002 := findReq(sysReqs, "SV-002")
	if sv002 == nil {
		t.Fatal("SV-002 not found in system diffs")
	}
	if sv002.State != types.StateAbsent {
		t.Errorf("expected SV-002 state 'absent', got %q", sv002.State)
	}
}

func TestFleet_AbsentRequirementHasSourceIndex(t *testing.T) {
	systemMissing := makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
	))

	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{systemMissing}, fleetOpts())

	sysReqs := findReqsBySource(diff.RequirementDiffs, 1)
	sv002 := findReq(sysReqs, "SV-002")
	if sv002 == nil {
		t.Fatal("SV-002 not found in system diffs")
	}
	if sv002.SourceIndex == nil || *sv002.SourceIndex != 1 {
		idx := -1
		if sv002.SourceIndex != nil {
			idx = *sv002.SourceIndex
		}
		t.Errorf("expected sourceIndex=1 for absent SV-002, got %d", idx)
	}
}

func TestFleet_AbsentRequirementInSummaryCounts(t *testing.T) {
	systemMissing := makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
	))

	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{systemMissing}, fleetOpts())

	if diff.Summary.Absent != 1 {
		t.Errorf("expected absent=1, got %d", diff.Summary.Absent)
	}
	if diff.Summary.Unchanged != 1 {
		t.Errorf("expected unchanged=1, got %d", diff.Summary.Unchanged)
	}
	if diff.Summary.Total != 2 {
		t.Errorf("expected total=2, got %d", diff.Summary.Total)
	}
}

// ---------------------------------------------------------------------------
// 9. Fleet mode timestamp and matching config
// ---------------------------------------------------------------------------

func TestFleet_IncludesTimestamp(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestFleet_MatchingConfigPopulated(t *testing.T) {
	diff := mustDiffHdf(t, buildFleetReference(), []hdf.HdfResults{buildFleetSystemA(), buildFleetSystemB()}, fleetOpts())

	if diff.Matching == nil {
		t.Fatal("expected matching config to be set")
	}
	if diff.Matching.PrimaryStrategy != stratExactID {
		t.Errorf("expected primaryStrategy %q, got %q", stratExactID, diff.Matching.PrimaryStrategy)
	}
}
