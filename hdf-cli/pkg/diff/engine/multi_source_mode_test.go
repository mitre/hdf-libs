package engine

import (
	"testing"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// ---------------------------------------------------------------------------
// MultiSource mode test fixtures
// ---------------------------------------------------------------------------

func buildMultiSourceScanA() hdf.HdfResults {
	return makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Failed, 0.5),
	))
}

func buildMultiSourceScanB() hdf.HdfResults {
	return makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Passed, 0.5),
	))
}

func multiSourceOpts() Options {
	return Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: types.ModeMultiSource,
		MatchStrategy:  stratExactID,
	}
}

// ---------------------------------------------------------------------------
// 1. Top-level metadata
// ---------------------------------------------------------------------------

func TestMultiSource_ComparisonModeIsMultiSource(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	if diff.ComparisonMode != types.ModeMultiSource {
		t.Errorf("expected comparisonMode 'multiSource', got %q", diff.ComparisonMode)
	}
}

func TestMultiSource_FormatVersion(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	if diff.FormatVersion != version100 {
		t.Errorf("expected formatVersion %q, got %q", version100, diff.FormatVersion)
	}
}

// ---------------------------------------------------------------------------
// 2. Sources with roles and labels
// ---------------------------------------------------------------------------

func TestMultiSource_HasTwoSources(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	if len(diff.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(diff.Sources))
	}
}

func TestMultiSource_FirstSourceRoleIsOld(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	if diff.Sources[0].Role != types.RoleOld {
		t.Errorf("expected first source role 'old', got %q", diff.Sources[0].Role)
	}
}

func TestMultiSource_SecondSourceRoleIsNew(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	if diff.Sources[1].Role != types.RoleNew {
		t.Errorf("expected second source role 'new', got %q", diff.Sources[1].Role)
	}
}

// The TS multiSource mode uses dataSource.name from the raw document for labels.
// The Go engine currently uses static default labels. This test verifies the
// current Go behavior with default labels when no dataSource is available.
func TestMultiSource_DefaultLabelsWhenNoDataSource(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	if diff.Sources[0].Label != "Old evaluation" {
		t.Errorf("expected first source label 'Old evaluation', got %q", diff.Sources[0].Label)
	}
	if diff.Sources[1].Label != "New evaluation" {
		t.Errorf("expected second source label 'New evaluation', got %q", diff.Sources[1].Label)
	}
}

// ---------------------------------------------------------------------------
// 3. Diff logic is identical to temporal
// ---------------------------------------------------------------------------

func TestMultiSource_SameRequirementStatesAsTemporal(t *testing.T) {
	scanA := buildMultiSourceScanA()
	scanB := buildMultiSourceScanB()

	multiDiff := mustDiffHdf(t, scanA, []hdf.HdfResults{scanB}, multiSourceOpts())

	temporalOpts := multiSourceOpts()
	temporalOpts.ComparisonMode = types.ModeTemporal
	temporalDiff := mustDiffHdf(t, scanA, []hdf.HdfResults{scanB}, temporalOpts)

	if len(multiDiff.RequirementDiffs) != len(temporalDiff.RequirementDiffs) {
		t.Fatalf("expected same number of requirementDiffs: multi=%d, temporal=%d",
			len(multiDiff.RequirementDiffs), len(temporalDiff.RequirementDiffs))
	}

	for _, temporalReq := range temporalDiff.RequirementDiffs {
		multiReq := findReq(multiDiff.RequirementDiffs, temporalReq.ID)
		if multiReq == nil {
			t.Errorf("requirement %s found in temporal but not multiSource", temporalReq.ID)
			continue
		}
		if multiReq.State != temporalReq.State {
			t.Errorf("requirement %s state mismatch: multi=%q, temporal=%q",
				temporalReq.ID, multiReq.State, temporalReq.State)
		}
	}
}

func TestMultiSource_SameSummaryCountsAsTemporal(t *testing.T) {
	scanA := buildMultiSourceScanA()
	scanB := buildMultiSourceScanB()

	multiDiff := mustDiffHdf(t, scanA, []hdf.HdfResults{scanB}, multiSourceOpts())

	temporalOpts := multiSourceOpts()
	temporalOpts.ComparisonMode = types.ModeTemporal
	temporalDiff := mustDiffHdf(t, scanA, []hdf.HdfResults{scanB}, temporalOpts)

	if multiDiff.Summary != temporalDiff.Summary {
		t.Errorf("summary mismatch:\nmulti:    %+v\ntemporal: %+v",
			multiDiff.Summary, temporalDiff.Summary)
	}
}

func TestMultiSource_SV002DetectedAsFixed(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	req := findReq(diff.RequirementDiffs, "SV-002")
	if req == nil {
		t.Fatal("SV-002 not found")
	}
	if req.State != types.StateFixed {
		t.Errorf("expected SV-002 state 'fixed', got %q", req.State)
	}
	if req.OldEffectiveStatus != statusFailed {
		t.Errorf("expected oldEffectiveStatus 'failed', got %q", req.OldEffectiveStatus)
	}
	if req.NewEffectiveStatus != statusPassed {
		t.Errorf("expected newEffectiveStatus 'passed', got %q", req.NewEffectiveStatus)
	}
}

// ---------------------------------------------------------------------------
// 4. Identical documents in multiSource mode
// ---------------------------------------------------------------------------

func TestMultiSource_IdenticalDocuments_AllUnchanged(t *testing.T) {
	scanA := buildMultiSourceScanA()
	diff := mustDiffHdf(t, scanA, []hdf.HdfResults{scanA}, multiSourceOpts())

	for _, req := range diff.RequirementDiffs {
		if req.State != types.StateUnchanged {
			t.Errorf("expected state 'unchanged' for %s, got %q", req.ID, req.State)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Timestamp is present
// ---------------------------------------------------------------------------

func TestMultiSource_IncludesTimestamp(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	if diff.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

// ---------------------------------------------------------------------------
// 6. Matching config is populated
// ---------------------------------------------------------------------------

func TestMultiSource_MatchingConfigPopulated(t *testing.T) {
	diff := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HdfResults{buildMultiSourceScanB()}, multiSourceOpts())

	if diff.Matching == nil {
		t.Fatal("expected matching config to be set")
	}
	if diff.Matching.PrimaryStrategy != stratExactID {
		t.Errorf("expected primaryStrategy %q, got %q", stratExactID, diff.Matching.PrimaryStrategy)
	}
}
