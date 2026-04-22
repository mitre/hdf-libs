package diff

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

// ---------------------------------------------------------------------------
// MultiSource mode test fixtures
// ---------------------------------------------------------------------------

func buildMultiSourceScanA() hdf.HDFResults {
	return makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Failed, 0.5),
	))
}

func buildMultiSourceScanB() hdf.HDFResults {
	return makeResults(makeBaseline("test-baseline", version100,
		makeRequirementWithTitle("SV-001", "Check A", hdf.Passed, 0.7),
		makeRequirementWithTitle("SV-002", "Check B", hdf.Passed, 0.5),
	))
}

func multiSourceOpts() Options {
	return Options{
		TrackedFields:  []string{fieldImpact, fieldSeverity, "tags"},
		ComparisonMode: ModeMultiSource,
		MatchStrategy:  stratExactID,
	}
}

// ---------------------------------------------------------------------------
// 1. Top-level metadata
// ---------------------------------------------------------------------------

func TestMultiSource_ComparisonModeIsMultiSource(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	if result.ComparisonMode != ModeMultiSource {
		t.Errorf("expected comparisonMode 'multiSource', got %q", result.ComparisonMode)
	}
}

func TestMultiSource_FormatVersion(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	if result.FormatVersion != version100 {
		t.Errorf("expected formatVersion %q, got %q", version100, result.FormatVersion)
	}
}

// ---------------------------------------------------------------------------
// 2. result.Sources with roles and labels
// ---------------------------------------------------------------------------

func TestMultiSource_HasTwoSources(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	if len(result.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(result.Sources))
	}
}

func TestMultiSource_FirstSourceRoleIsOld(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	if result.Sources[0].Role != RoleOld {
		t.Errorf("expected first source role 'old', got %q", result.Sources[0].Role)
	}
}

func TestMultiSource_SecondSourceRoleIsNew(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	if result.Sources[1].Role != RoleNew {
		t.Errorf("expected second source role 'new', got %q", result.Sources[1].Role)
	}
}

// The TS multiSource mode uses tool.name from the raw document for labels.
// The Go engine currently uses static default labels. This test verifies the
// current Go behavior with default labels when no tool field is available.
func TestMultiSource_DefaultLabelsWhenNoTool(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	if result.Sources[0].Label != "Old evaluation" {
		t.Errorf("expected first source label 'Old evaluation', got %q", result.Sources[0].Label)
	}
	if result.Sources[1].Label != "New evaluation" {
		t.Errorf("expected second source label 'New evaluation', got %q", result.Sources[1].Label)
	}
}

// ---------------------------------------------------------------------------
// 3. Diff logic is identical to temporal
// ---------------------------------------------------------------------------

func TestMultiSource_SameRequirementStatesAsTemporal(t *testing.T) {
	scanA := buildMultiSourceScanA()
	scanB := buildMultiSourceScanB()

	multiDiff := mustDiffHdf(t, scanA, []hdf.HDFResults{scanB}, multiSourceOpts())

	temporalOpts := multiSourceOpts()
	temporalOpts.ComparisonMode = ModeTemporal
	temporalDiff := mustDiffHdf(t, scanA, []hdf.HDFResults{scanB}, temporalOpts)

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

	multiDiff := mustDiffHdf(t, scanA, []hdf.HDFResults{scanB}, multiSourceOpts())

	temporalOpts := multiSourceOpts()
	temporalOpts.ComparisonMode = ModeTemporal
	temporalDiff := mustDiffHdf(t, scanA, []hdf.HDFResults{scanB}, temporalOpts)

	if multiDiff.Summary != temporalDiff.Summary {
		t.Errorf("summary mismatch:\nmulti:    %+v\ntemporal: %+v",
			multiDiff.Summary, temporalDiff.Summary)
	}
}

func TestMultiSource_SV002DetectedAsFixed(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	req := findReq(result.RequirementDiffs, "SV-002")
	if req == nil {
		t.Fatal("SV-002 not found")
	}
	if req.State != StateFixed {
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
	result := mustDiffHdf(t, scanA, []hdf.HDFResults{scanA}, multiSourceOpts())

	for _, req := range result.RequirementDiffs {
		if req.State != StateUnchanged {
			t.Errorf("expected state 'unchanged' for %s, got %q", req.ID, req.State)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. result.Timestamp is present
// ---------------------------------------------------------------------------

func TestMultiSource_IncludesTimestamp(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	if result.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

// ---------------------------------------------------------------------------
// 6. result.Matching config is populated
// ---------------------------------------------------------------------------

func TestMultiSource_MatchingConfigPopulated(t *testing.T) {
	result := mustDiffHdf(t, buildMultiSourceScanA(), []hdf.HDFResults{buildMultiSourceScanB()}, multiSourceOpts())

	if result.Matching == nil {
		t.Fatal("expected matching config to be set")
	}
	if result.Matching.PrimaryStrategy != stratExactID {
		t.Errorf("expected primaryStrategy %q, got %q", stratExactID, result.Matching.PrimaryStrategy)
	}
}
