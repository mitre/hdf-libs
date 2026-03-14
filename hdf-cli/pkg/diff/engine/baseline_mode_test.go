package engine

import (
	"testing"
	"time"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// ---------------------------------------------------------------------------
// Baseline mode test fixtures
// ---------------------------------------------------------------------------

// buildBaselineScanBefore builds the "golden" document matching scan-before.json.
// 5 requirements: SV-001(failed), SV-002(passed), SV-003(passed), SV-004(failed), SV-005(passed).
func buildBaselineScanBefore() hdf.HdfResults {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	return hdf.HdfResults{
		Baselines: []hdf.EvaluatedBaseline{
			makeBaseline("rhel9-stig-baseline", version100,
				makeRequirementWithTitle("SV-001", "Ensure SSH root login is disabled", hdf.Failed, 0.7),
				makeRequirementWithTitle("SV-002", "Ensure password complexity is configured", hdf.Passed, 0.5),
				makeRequirementWithTitle("SV-003", "Ensure audit logging is enabled", hdf.Passed, 0.7),
				makeRequirementWithTitle("SV-004", "Ensure FIPS mode is enabled", hdf.Failed, 0.7),
				makeRequirementWithTitle("SV-005", "Ensure NTP is configured", hdf.Passed, 0.3),
			),
		},
		Timestamp: &ts,
	}
}

// buildBaselineScanAfter builds the "current" document matching scan-after.json.
// 5 requirements: SV-001(passed), SV-002(passed), SV-003(failed), SV-005(passed,impact=0), SV-006(passed).
// SV-004 removed, SV-006 added, SV-005 impact changed, baseline version bumped to 1.1.0.
func buildBaselineScanAfter() hdf.HdfResults {
	ts := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	return hdf.HdfResults{
		Baselines: []hdf.EvaluatedBaseline{
			makeBaseline("rhel9-stig-baseline", version110,
				makeRequirementWithTitle("SV-001", "Ensure SSH root login is disabled", hdf.Passed, 0.7),
				makeRequirementWithTitle("SV-002", "Ensure password complexity is configured", hdf.Passed, 0.5),
				makeRequirementWithTitle("SV-003", "Ensure audit logging is enabled", hdf.Failed, 0.7),
				makeRequirementWithTitle("SV-005", "Ensure NTP is configured", hdf.Passed, 0.0),
				makeRequirementWithTitle("SV-006", "Ensure SELinux is enforcing", hdf.Passed, 0.7),
			),
		},
		Timestamp: &ts,
	}
}

func baselineOpts() Options {
	return Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: types.ModeBaseline,
		MatchStrategy:  stratExactID,
	}
}

// ---------------------------------------------------------------------------
// 1. Top-level metadata
// ---------------------------------------------------------------------------

func TestBaseline_ComparisonModeIsBaseline(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	if diff.ComparisonMode != types.ModeBaseline {
		t.Errorf("expected comparisonMode 'baseline', got %q", diff.ComparisonMode)
	}
}

func TestBaseline_FormatVersion(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	if diff.FormatVersion != version100 {
		t.Errorf("expected formatVersion %q, got %q", version100, diff.FormatVersion)
	}
}

func TestBaseline_IncludesTimestamp(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	if diff.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

// ---------------------------------------------------------------------------
// 2. Sources with correct roles and labels
// ---------------------------------------------------------------------------

func TestBaseline_HasTwoSources(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	if len(diff.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(diff.Sources))
	}
}

func TestBaseline_FirstSourceRoleIsGolden(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	if diff.Sources[0].Role != types.RoleGolden {
		t.Errorf("expected first source role 'golden', got %q", diff.Sources[0].Role)
	}
}

func TestBaseline_SecondSourceRoleIsNew(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	if diff.Sources[1].Role != types.RoleNew {
		t.Errorf("expected second source role 'new', got %q", diff.Sources[1].Role)
	}
}

func TestBaseline_FirstSourceLabelIsGoldenBaseline(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	if diff.Sources[0].Label != "Golden baseline" {
		t.Errorf("expected first source label 'Golden baseline', got %q", diff.Sources[0].Label)
	}
}

func TestBaseline_SecondSourceLabelIsCurrentScan(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	if diff.Sources[1].Label != "Current scan" {
		t.Errorf("expected second source label 'Current scan', got %q", diff.Sources[1].Label)
	}
}

// ---------------------------------------------------------------------------
// 3. Diff logic is identical to temporal
// ---------------------------------------------------------------------------

func TestBaseline_SameRequirementDiffsAsTemporal(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()

	baselineDiff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	temporalOpts := baselineOpts()
	temporalOpts.ComparisonMode = types.ModeTemporal
	temporalDiff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, temporalOpts)

	if len(baselineDiff.RequirementDiffs) != len(temporalDiff.RequirementDiffs) {
		t.Fatalf("expected same number of requirementDiffs: baseline=%d, temporal=%d",
			len(baselineDiff.RequirementDiffs), len(temporalDiff.RequirementDiffs))
	}

	for _, temporalReq := range temporalDiff.RequirementDiffs {
		baselineReq := findReq(baselineDiff.RequirementDiffs, temporalReq.ID)
		if baselineReq == nil {
			t.Errorf("requirement %s found in temporal but not baseline", temporalReq.ID)
			continue
		}
		if baselineReq.State != temporalReq.State {
			t.Errorf("requirement %s state mismatch: baseline=%q, temporal=%q",
				temporalReq.ID, baselineReq.State, temporalReq.State)
		}
		if baselineReq.OldEffectiveStatus != temporalReq.OldEffectiveStatus {
			t.Errorf("requirement %s oldEffectiveStatus mismatch: baseline=%q, temporal=%q",
				temporalReq.ID, baselineReq.OldEffectiveStatus, temporalReq.OldEffectiveStatus)
		}
		if baselineReq.NewEffectiveStatus != temporalReq.NewEffectiveStatus {
			t.Errorf("requirement %s newEffectiveStatus mismatch: baseline=%q, temporal=%q",
				temporalReq.ID, baselineReq.NewEffectiveStatus, temporalReq.NewEffectiveStatus)
		}
	}
}

func TestBaseline_SameSummaryCountsAsTemporal(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()

	baselineDiff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	temporalOpts := baselineOpts()
	temporalOpts.ComparisonMode = types.ModeTemporal
	temporalDiff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, temporalOpts)

	if baselineDiff.Summary != temporalDiff.Summary {
		t.Errorf("summary mismatch:\nbaseline: %+v\ntemporal: %+v",
			baselineDiff.Summary, temporalDiff.Summary)
	}
}

func TestBaseline_SameBaselineDiffsAsTemporal(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()

	baselineDiff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	temporalOpts := baselineOpts()
	temporalOpts.ComparisonMode = types.ModeTemporal
	temporalDiff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, temporalOpts)

	if len(baselineDiff.BaselineDiffs) != len(temporalDiff.BaselineDiffs) {
		t.Fatalf("baseline diffs count mismatch: baseline=%d, temporal=%d",
			len(baselineDiff.BaselineDiffs), len(temporalDiff.BaselineDiffs))
	}

	for i, bd := range baselineDiff.BaselineDiffs {
		td := temporalDiff.BaselineDiffs[i]
		if bd.Name != td.Name || bd.State != td.State || bd.OldVersion != td.OldVersion || bd.NewVersion != td.NewVersion {
			t.Errorf("baseline diff %d mismatch:\nbaseline: %+v\ntemporal: %+v", i, bd, td)
		}
	}
}

func TestBaseline_SV001MarkedAsFixed(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	req := findReq(diff.RequirementDiffs, "SV-001")
	if req == nil {
		t.Fatal("SV-001 not found")
	}
	if req.State != types.StateFixed {
		t.Errorf("expected SV-001 state 'fixed', got %q", req.State)
	}
}

func TestBaseline_SV003MarkedAsRegressed(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	req := findReq(diff.RequirementDiffs, "SV-003")
	if req == nil {
		t.Fatal("SV-003 not found")
	}
	if req.State != types.StateRegressed {
		t.Errorf("expected SV-003 state 'regressed', got %q", req.State)
	}
}

// ---------------------------------------------------------------------------
// 3b. Baseline version diff detected in baseline mode
// ---------------------------------------------------------------------------

func TestBaseline_BaselineVersionDiffDetected(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	currentDoc := buildBaselineScanAfter()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{currentDoc}, baselineOpts())

	// The baseline version changed from 1.0.0 to 1.1.0, should be "updated"
	bd := findBaselineDiff(diff.BaselineDiffs, "rhel9-stig-baseline")
	if bd == nil {
		t.Fatal("rhel9-stig-baseline not found in baseline diffs")
	}
	if bd.State != types.StateUpdated {
		t.Errorf("expected baseline state 'updated', got %q", bd.State)
	}
	if bd.OldVersion != version100 {
		t.Errorf("expected oldVersion %q, got %q", version100, bd.OldVersion)
	}
	if bd.NewVersion != version110 {
		t.Errorf("expected newVersion %q, got %q", version110, bd.NewVersion)
	}
}

// ---------------------------------------------------------------------------
// 4. Identical documents in baseline mode
// ---------------------------------------------------------------------------

func TestBaseline_IdenticalDocuments_AllUnchanged(t *testing.T) {
	goldenDoc := buildBaselineScanBefore()
	diff := mustDiffHdf(t, goldenDoc, []hdf.HdfResults{goldenDoc}, baselineOpts())

	for _, req := range diff.RequirementDiffs {
		if req.State != types.StateUnchanged {
			t.Errorf("expected state 'unchanged' for %s, got %q", req.ID, req.State)
		}
	}
}
