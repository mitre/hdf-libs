package render

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testFixture builds an HdfComparison with mixed states for testing.
func testFixture() types.HdfComparison {
	oldImpact := 0.7
	newImpact := 0.5

	return types.HdfComparison{
		FormatVersion:  "1.0.0",
		ComparisonMode: types.ModeTemporal,
		Timestamp:      "2026-03-14T12:00:00Z",
		Sources: []types.Source{
			{Role: types.RoleOld, Label: "old-scan", AssessmentTimestamp: "2026-03-01T10:00:00Z"},
			{Role: types.RoleNew, Label: "new-scan", AssessmentTimestamp: "2026-03-14T10:00:00Z"},
		},
		Summary: types.ComparisonSummary{
			Fixed:             1,
			Regressed:         1,
			New:               1,
			Absent:            1,
			Unchanged:         1,
			Updated:           1,
			Total:             6,
			MatchedCount:      4,
			UnmatchedOldCount: 1,
			UnmatchedNewCount: 1,
		},
		RequirementDiffs: []types.RequirementDiff{
			{
				ID:                 "V-1001",
				State:              types.StateFixed,
				Title:              "Fix SSH Config",
				OldEffectiveStatus: "failed",
				NewEffectiveStatus: "passed",
				ChangeReasons:      []types.ChangeReason{types.ReasonResultChanged},
				Before:             &hdf.EvaluatedRequirement{},
				After:              &hdf.EvaluatedRequirement{},
				FieldChanges:       []types.FieldChange{},
			},
			{
				ID:                 "V-1002",
				State:              types.StateRegressed,
				Title:              "Ensure Firewall",
				OldEffectiveStatus: "passed",
				NewEffectiveStatus: "failed",
				ChangeReasons:      []types.ChangeReason{types.ReasonResultChanged},
				Before:             &hdf.EvaluatedRequirement{},
				After:              &hdf.EvaluatedRequirement{},
				FieldChanges:       []types.FieldChange{},
			},
			{
				ID:                 "V-1003",
				State:              types.StateNew,
				Title:              "New Audit Rule",
				NewEffectiveStatus: "passed",
				ChangeReasons:      []types.ChangeReason{types.ReasonControlMapped},
				After:              &hdf.EvaluatedRequirement{},
				FieldChanges:       []types.FieldChange{},
			},
			{
				ID:                 "V-1004",
				State:              types.StateAbsent,
				Title:              "Removed Check",
				OldEffectiveStatus: "passed",
				ChangeReasons:      []types.ChangeReason{},
				Before:             &hdf.EvaluatedRequirement{},
				FieldChanges:       []types.FieldChange{},
			},
			{
				ID:                 "V-1005",
				State:              types.StateUnchanged,
				Title:              "Stable Control",
				OldEffectiveStatus: "passed",
				NewEffectiveStatus: "passed",
				ChangeReasons:      []types.ChangeReason{},
				Before:             &hdf.EvaluatedRequirement{},
				After:              &hdf.EvaluatedRequirement{},
				FieldChanges:       []types.FieldChange{},
			},
			{
				ID:                 "V-1006",
				State:              types.StateUpdated,
				Title:              "Updated Impact",
				OldEffectiveStatus: "passed",
				NewEffectiveStatus: "passed",
				OldImpact:          &oldImpact,
				NewImpact:          &newImpact,
				ChangeReasons:      []types.ChangeReason{types.ReasonImpactChanged},
				Before:             &hdf.EvaluatedRequirement{},
				After:              &hdf.EvaluatedRequirement{},
				FieldChanges: []types.FieldChange{
					{Op: types.OpReplace, Path: "/impact", OldValue: 0.7, NewValue: 0.5},
				},
			},
		},
		BaselineDiffs: []types.BaselineDiff{},
	}
}

// ─── Render dispatch tests ──────────────────────────────────────────────────

func TestRender_DispatchJSON(t *testing.T) {
	comp := testFixture()
	out, err := Render(comp, "json", Options{Detail: DetailFull})
	require.NoError(t, err)
	assert.Contains(t, out, `"formatVersion"`)
}

func TestRender_DispatchMarkdown(t *testing.T) {
	comp := testFixture()
	out, err := Render(comp, "markdown", Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Contains(t, out, "## HDF Comparison Summary")
}

func TestRender_DispatchTerminal(t *testing.T) {
	comp := testFixture()
	out, err := Render(comp, "terminal", Options{Detail: DetailControl, NoColor: true})
	require.NoError(t, err)
	assert.Contains(t, out, "Summary:")
}

func TestRender_DispatchCSV(t *testing.T) {
	comp := testFixture()
	out, err := Render(comp, "csv", Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Contains(t, out, "ID,")
}

func TestRender_UnknownFormat(t *testing.T) {
	comp := testFixture()
	_, err := Render(comp, "xml", Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

// ─── JSON renderer tests ────────────────────────────────────────────────────

func TestJSON_FullDetail_ValidJSON(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailFull})
	require.NoError(t, err)

	// Should be valid JSON that round-trips
	var parsed types.HdfComparison
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)
	assert.Equal(t, comp.FormatVersion, parsed.FormatVersion)
	assert.Equal(t, comp.ComparisonMode, parsed.ComparisonMode)
	assert.Equal(t, len(comp.RequirementDiffs), len(parsed.RequirementDiffs))
}

func TestJSON_SummaryDetail_OnlySummaryFields(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	// Should contain only summary-related fields
	assert.Contains(t, parsed, "formatVersion")
	assert.Contains(t, parsed, "comparisonMode")
	assert.Contains(t, parsed, "summary")

	// Should NOT contain full-document fields
	assert.NotContains(t, parsed, "requirementDiffs")
	assert.NotContains(t, parsed, "sources")
	assert.NotContains(t, parsed, "baselineDiffs")
}

func TestJSON_ControlDetail_NoBeforeAfter(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	// requirementDiffs should exist
	diffs, ok := parsed["requirementDiffs"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, diffs)

	// Each diff should NOT have before/after
	for _, d := range diffs {
		diffMap, ok := d.(map[string]any)
		require.True(t, ok)
		assert.NotContains(t, diffMap, "before")
		assert.NotContains(t, diffMap, "after")
	}
}

func TestJSON_DefaultDetailIsControl(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	diffs, ok := parsed["requirementDiffs"].([]any)
	require.True(t, ok)
	for _, d := range diffs {
		diffMap := d.(map[string]any)
		assert.NotContains(t, diffMap, "before")
		assert.NotContains(t, diffMap, "after")
	}
}

func TestJSON_FilterStates(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{
		Detail:       DetailFull,
		FilterStates: []types.RequirementState{types.StateFixed, types.StateRegressed},
	})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	diffs := parsed["requirementDiffs"].([]any)
	assert.Equal(t, 2, len(diffs))
}

// ─── Markdown renderer tests ───────────────────────────────────────────────

func TestMarkdown_ContainsSummaryTableHeaders(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	assert.Contains(t, out, "## HDF Comparison Summary")
	assert.Contains(t, out, "| Metric | Count |")
	assert.Contains(t, out, "| Fixed | 1 |")
	assert.Contains(t, out, "| **Total** | **6** |")
}

func TestMarkdown_SummaryOnly(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)

	assert.Contains(t, out, "## HDF Comparison Summary")
	// Should NOT contain per-state sections
	assert.NotContains(t, out, "### Fixed")
	assert.NotContains(t, out, "### Regressed")
}

func TestMarkdown_ContainsPerStateSectionHeaders(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	assert.Contains(t, out, "### Fixed (1)")
	assert.Contains(t, out, "### Regressed (1)")
	assert.Contains(t, out, "### New (1)")
	assert.Contains(t, out, "### Absent (1)")
	assert.Contains(t, out, "### Updated (1)")
	assert.Contains(t, out, "### Unchanged (1)")
}

func TestMarkdown_ControlDetailHasBasicTable(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	assert.Contains(t, out, "| ID | Title | Old Status | New Status |")
	assert.Contains(t, out, "| V-1001 | Fix SSH Config | failed | passed |")
}

func TestMarkdown_FullDetailHasExtendedTable(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{Detail: DetailFull})
	require.NoError(t, err)

	assert.Contains(t, out, "| ID | Title | Old Status | New Status | Change Reasons | Field Changes |")
	assert.Contains(t, out, "/impact")
}

func TestMarkdown_FilterStatesShowsOnlyRequestedSections(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{
		Detail:       DetailControl,
		FilterStates: []types.RequirementState{types.StateFixed},
	})
	require.NoError(t, err)

	assert.Contains(t, out, "### Fixed (1)")
	assert.NotContains(t, out, "### Regressed")
	assert.NotContains(t, out, "### New")
}

// ─── Terminal renderer tests ────────────────────────────────────────────────

func TestTerminal_ContainsPlusMinusTildeSymbols(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: true})
	require.NoError(t, err)

	// Fixed gets +
	assert.Contains(t, out, "  + V-1001")
	// Regressed gets -
	assert.Contains(t, out, "  - V-1002")
	// New gets +
	assert.Contains(t, out, "  + V-1003")
	// Absent gets -
	assert.Contains(t, out, "  - V-1004")
	// Updated gets ~
	assert.Contains(t, out, "  ~ V-1006")
}

func TestTerminal_NoColorHasNoANSI(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: true})
	require.NoError(t, err)

	assert.NotContains(t, out, "\x1b")
}

func TestTerminal_ColorHasANSI(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: false})
	require.NoError(t, err)

	assert.Contains(t, out, "\x1b[")
}

func TestTerminal_SummaryLine(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailControl, NoColor: true})
	require.NoError(t, err)

	assert.Contains(t, out, "Summary: 1 fixed, 1 regressed, 1 new, 1 absent, 1 unchanged, 1 updated (6 total)")
}

func TestTerminal_SummaryOnlyMode(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailSummary, NoColor: true})
	require.NoError(t, err)

	assert.Contains(t, out, "Summary:")
	// Should not contain requirement lines
	assert.NotContains(t, out, "V-1001")
}

func TestTerminal_ControlModeSkipsUnchanged(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailControl, NoColor: true})
	require.NoError(t, err)

	// Unchanged V-1005 should not appear in control mode
	assert.NotContains(t, out, "V-1005")
}

func TestTerminal_FullModeShowsUnchanged(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: true})
	require.NoError(t, err)

	assert.Contains(t, out, "V-1005")
}

func TestTerminal_FullModeShowsChangeReasons(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: true})
	require.NoError(t, err)

	assert.Contains(t, out, "[resultChanged]")
}

func TestTerminal_HeaderContainsMode(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailSummary, NoColor: true})
	require.NoError(t, err)

	assert.Contains(t, out, "HDF Comparison: temporal")
}

func TestTerminal_HeaderContainsTimestamps(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailSummary, NoColor: true})
	require.NoError(t, err)

	assert.Contains(t, out, "2026-03-01")
	assert.Contains(t, out, "2026-03-14")
}

// ─── CSV renderer tests ────────────────────────────────────────────────────

func TestCSV_FirstLineIsHeader(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	lines := strings.Split(out, "\n")
	require.NotEmpty(t, lines)
	assert.Equal(t, "ID,Title,State,Old Status,New Status,Impact (Old),Impact (New),Change Reasons", lines[0])
}

func TestCSV_CorrectRowCount(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// 1 header + 6 data rows
	assert.Equal(t, 7, len(records))
}

func TestCSV_FullDetailHasFieldChangesColumn(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailFull})
	require.NoError(t, err)

	lines := strings.Split(out, "\n")
	require.NotEmpty(t, lines)
	assert.Contains(t, lines[0], "Field Changes")
}

func TestCSV_ControlDetailNoFieldChangesColumn(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	lines := strings.Split(out, "\n")
	require.NotEmpty(t, lines)
	assert.NotContains(t, lines[0], "Field Changes")
}

func TestCSV_FilterStatesReducesRows(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{
		Detail:       DetailControl,
		FilterStates: []types.RequirementState{types.StateFixed},
	})
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// 1 header + 1 data row
	assert.Equal(t, 2, len(records))
}

func TestCSV_ProperEscaping(t *testing.T) {
	comp := testFixture()
	// Add a requirement with commas and quotes in the title
	comp.RequirementDiffs = append(comp.RequirementDiffs, types.RequirementDiff{
		ID:            "V-1007",
		State:         types.StateNew,
		Title:         `Title with "quotes" and, commas`,
		ChangeReasons: []types.ChangeReason{},
		FieldChanges:  []types.FieldChange{},
	})
	comp.Summary.Total = 7

	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	// CSV parser should handle it correctly
	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// Find the row with our special title
	found := false
	for _, row := range records {
		if row[0] == "V-1007" {
			assert.Equal(t, `Title with "quotes" and, commas`, row[1])
			found = true
		}
	}
	assert.True(t, found, "should find row with V-1007")
}

// ─── Filter tests ───────────────────────────────────────────────────────────

func TestFilterRequirements_EmptyFilter(t *testing.T) {
	comp := testFixture()
	filtered := filterRequirements(comp.RequirementDiffs, Options{})
	assert.Equal(t, len(comp.RequirementDiffs), len(filtered))
}

func TestFilterRequirements_SingleState(t *testing.T) {
	comp := testFixture()
	filtered := filterRequirements(comp.RequirementDiffs, Options{
		FilterStates: []types.RequirementState{types.StateFixed},
	})
	assert.Equal(t, 1, len(filtered))
	assert.Equal(t, types.StateFixed, filtered[0].State)
}

func TestFilterRequirements_MultipleStates(t *testing.T) {
	comp := testFixture()
	filtered := filterRequirements(comp.RequirementDiffs, Options{
		FilterStates: []types.RequirementState{types.StateFixed, types.StateRegressed, types.StateNew},
	})
	assert.Equal(t, 3, len(filtered))
}
