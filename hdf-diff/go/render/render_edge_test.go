package render

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	diff "github.com/mitre/hdf-libs/hdf-diff/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Helper: fixture for field-change edge cases ────────────────────────────

func fieldChangeFixture() diff.HdfComparison {
	return diff.HdfComparison{
		FormatVersion:  "1.0.0",
		ComparisonMode: diff.ModeTemporal,
		Timestamp:      "2026-03-14T12:00:00Z",
		Sources: []diff.Source{
			{Role: diff.RoleOld, Label: "old-scan", AssessmentTimestamp: "2026-03-01T10:00:00Z"},
			{Role: diff.RoleNew, Label: "new-scan", AssessmentTimestamp: "2026-03-14T10:00:00Z"},
		},
		Summary: diff.ComparisonSummary{
			Updated: 1,
			Total:   1,
		},
		RequirementDiffs: []diff.RequirementDiff{
			{
				ID:                 "V-2001",
				State:              diff.StateUpdated,
				Title:              "Test Req",
				OldEffectiveStatus: "passed",
				NewEffectiveStatus: "passed",
				ChangeReasons:      []diff.ChangeReason{diff.ReasonMetadataChanged},
				Before:             &hdf.EvaluatedRequirement{},
				After:              &hdf.EvaluatedRequirement{},
				FieldChanges: []diff.FieldChange{
					{Op: diff.OpAdd, Path: "tags.newTag", NewValue: "added-val"},
					{Op: diff.OpRemove, Path: "tags.oldTag", OldValue: "removed-val"},
					{Op: diff.OpReplace, Path: "impact", OldValue: 0.3, NewValue: 0.7},
				},
			},
		},
		BaselineDiffs: []diff.BaselineDiff{},
	}
}

// ─── Render dispatch: options pass-through ──────────────────────────────────

func TestRender_OptionsPassThrough(t *testing.T) {
	comp := testFixture()
	fromRender, err := Render(comp, "json", Options{Detail: DetailSummary})
	require.NoError(t, err)
	fromDirect, err := JSON(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)
	assert.Equal(t, fromDirect, fromRender)
}

// ─── JSON: round-trip full detail ───────────────────────────────────────────

func TestJSON_FullDetail_RoundTrip(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailFull})
	require.NoError(t, err)

	var parsed diff.HdfComparison
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	assert.Equal(t, comp.FormatVersion, parsed.FormatVersion)
	assert.Equal(t, comp.ComparisonMode, parsed.ComparisonMode)
	assert.Equal(t, comp.Summary.Total, parsed.Summary.Total)
	assert.Equal(t, len(comp.RequirementDiffs), len(parsed.RequirementDiffs))

	// Verify each requirement's state is preserved
	for i, req := range comp.RequirementDiffs {
		assert.Equal(t, req.ID, parsed.RequirementDiffs[i].ID)
		assert.Equal(t, req.State, parsed.RequirementDiffs[i].State)
	}
}

func TestJSON_FullDetail_IncludesBeforeAfterOnMatched(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailFull})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	diffs := parsed["requirementDiffs"].([]any)
	// V-1001 (fixed) should have both before and after
	for _, d := range diffs {
		diffMap := d.(map[string]any)
		state := diffMap["state"].(string)
		if state == "fixed" || state == "regressed" || state == "updated" || state == "unchanged" {
			assert.Contains(t, diffMap, "before", "matched requirement %s should have 'before'", diffMap["id"])
			assert.Contains(t, diffMap, "after", "matched requirement %s should have 'after'", diffMap["id"])
		}
	}
}

func TestJSON_SummaryDetail_HasCorrectCounts(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	summary := parsed["summary"].(map[string]any)
	assert.Equal(t, float64(comp.Summary.Fixed), summary["fixed"])
	assert.Equal(t, float64(comp.Summary.Regressed), summary["regressed"])
	assert.Equal(t, float64(comp.Summary.New), summary["new"])
	assert.Equal(t, float64(comp.Summary.Absent), summary["absent"])
	assert.Equal(t, float64(comp.Summary.Unchanged), summary["unchanged"])
	assert.Equal(t, float64(comp.Summary.Updated), summary["updated"])
	assert.Equal(t, float64(comp.Summary.Total), summary["total"])
}

func TestJSON_ControlDetail_RetainsIDStateTitle(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	diffs := parsed["requirementDiffs"].([]any)
	for _, d := range diffs {
		diffMap := d.(map[string]any)
		assert.Contains(t, diffMap, "id")
		assert.Contains(t, diffMap, "state")
		// Title may be omitted if empty but should be string when present
		if _, ok := diffMap["title"]; ok {
			_, isStr := diffMap["title"].(string)
			assert.True(t, isStr)
		}
	}
}

func TestJSON_FilterStates_AllMatchRequestedState(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{
		Detail:       DetailControl,
		FilterStates: []diff.RequirementState{diff.StateFixed},
	})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	diffs := parsed["requirementDiffs"].([]any)
	require.NotEmpty(t, diffs, "should have at least one fixed requirement")
	for _, d := range diffs {
		diffMap := d.(map[string]any)
		assert.Equal(t, "fixed", diffMap["state"])
	}
}

func TestJSON_FilterStates_NonExistentState(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{
		Detail:       DetailControl,
		FilterStates: []diff.RequirementState{"critical"},
	})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	diffs := parsed["requirementDiffs"].([]any)
	assert.Empty(t, diffs)
}

func TestJSON_FullDetail_FilterStatesPreservesBeforeAfter(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{
		Detail:       DetailFull,
		FilterStates: []diff.RequirementState{diff.StateRegressed},
	})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	diffs := parsed["requirementDiffs"].([]any)
	require.NotEmpty(t, diffs)
	for _, d := range diffs {
		diffMap := d.(map[string]any)
		assert.Equal(t, "regressed", diffMap["state"])
		assert.Contains(t, diffMap, "before")
		assert.Contains(t, diffMap, "after")
	}
}

// ─── Markdown: default detail level ─────────────────────────────────────────

func TestMarkdown_DefaultIsControlDetail(t *testing.T) {
	comp := testFixture()
	outputDefault, err := Markdown(comp, Options{})
	require.NoError(t, err)
	outputControl, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Equal(t, outputControl, outputDefault)
}

func TestMarkdown_EmptyStateSectionsShowNone(t *testing.T) {
	// Create a comparison with only fixed requirements
	comp := testFixture()
	comp.RequirementDiffs = []diff.RequirementDiff{comp.RequirementDiffs[0]}
	out, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	// States like regressed, new, absent, updated, unchanged should show (none)
	assert.Contains(t, out, "(none)")
	// Fixed section should NOT have (none)
	fixedIdx := strings.Index(out, "### Fixed (1)")
	regressedIdx := strings.Index(out, "### Regressed (0)")
	require.Greater(t, regressedIdx, fixedIdx)
	between := out[fixedIdx:regressedIdx]
	assert.NotContains(t, between, "(none)")
}

func TestMarkdown_FullDetail_AddRemoveFieldChangeOps(t *testing.T) {
	comp := fieldChangeFixture()
	out, err := Markdown(comp, Options{Detail: DetailFull})
	require.NoError(t, err)

	assert.Contains(t, out, "+tags.newTag")
	assert.Contains(t, out, "-tags.oldTag")
	assert.Contains(t, out, "impact:")
}

// emptyTitleReq builds a single-diff comparison with an empty title for testing.
func emptyTitleReq(id string, state diff.RequirementState, oldStatus, newStatus string) diff.HdfComparison {
	comp := testFixture()
	comp.RequirementDiffs = []diff.RequirementDiff{
		{
			ID:                 id,
			State:              state,
			Title:              "",
			OldEffectiveStatus: oldStatus,
			NewEffectiveStatus: newStatus,
			ChangeReasons:      []diff.ChangeReason{diff.ReasonResultChanged},
			Before:             &hdf.EvaluatedRequirement{},
			After:              &hdf.EvaluatedRequirement{},
			FieldChanges:       []diff.FieldChange{},
		},
	}
	return comp
}

func TestMarkdown_EmptyTitle_FullDetail(t *testing.T) {
	comp := emptyTitleReq("V-3001", diff.StateFixed, "failed", "passed")
	out, err := Markdown(comp, Options{Detail: DetailFull})
	require.NoError(t, err)
	assert.Contains(t, out, "### Fixed (1)")
	assert.Contains(t, out, "V-3001")
}

func TestMarkdown_EmptyTitle_ControlDetail(t *testing.T) {
	comp := emptyTitleReq("V-3002", diff.StateRegressed, "passed", "failed")
	out, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Contains(t, out, "### Regressed (1)")
	assert.Contains(t, out, "V-3002")
}

func TestMarkdown_PipeEscapingInTableCells(t *testing.T) {
	comp := testFixture()
	comp.RequirementDiffs = []diff.RequirementDiff{
		{
			ID:                 "V-3003",
			State:              diff.StateFixed,
			Title:              "Ensure foo|bar disabled",
			OldEffectiveStatus: "failed",
			NewEffectiveStatus: "passed",
			ChangeReasons:      []diff.ChangeReason{},
			FieldChanges:       []diff.FieldChange{},
		},
	}
	out, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Contains(t, out, "foo&#124;bar")
	assert.NotContains(t, out, "foo|bar")
}

func TestMarkdown_MultipleSameStateGrouping(t *testing.T) {
	comp := testFixture()
	comp.RequirementDiffs = []diff.RequirementDiff{
		{
			ID:            "V-4001",
			State:         diff.StateFixed,
			Title:         "First",
			ChangeReasons: []diff.ChangeReason{},
			FieldChanges:  []diff.FieldChange{},
		},
		{
			ID:            "V-4002",
			State:         diff.StateFixed,
			Title:         "Second",
			ChangeReasons: []diff.ChangeReason{},
			FieldChanges:  []diff.FieldChange{},
		},
	}
	out, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Contains(t, out, "### Fixed (2)")
	assert.Contains(t, out, "V-4001")
	assert.Contains(t, out, "V-4002")
}

func TestMarkdown_NoTrailingWhitespaceOnTableRows(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "|") {
			// Table rows should end with |
			trimmed := strings.TrimRight(line, " \t")
			assert.True(t, strings.HasSuffix(trimmed, "|"),
				"table row should end with |: %q", line)
		}
	}
}

func TestMarkdown_SummaryTableStructure(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)

	assert.Contains(t, out, "| Metric | Count |")
	assert.Contains(t, out, "|--------|-------|")
	assert.Contains(t, out, "Fixed")
	assert.Contains(t, out, "Regressed")
	assert.Contains(t, out, "New")
	assert.Contains(t, out, "Absent")
	assert.Contains(t, out, "Unchanged")
	assert.Contains(t, out, "Updated")
	assert.Contains(t, out, "**Total**")
}

func TestMarkdown_SummaryDetailNotContainIDColumn(t *testing.T) {
	comp := testFixture()
	out, err := Markdown(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)
	assert.NotContains(t, out, "| ID |")
}

// ─── Terminal: default detail level ─────────────────────────────────────────

func TestTerminal_DefaultIsControlDetail(t *testing.T) {
	comp := testFixture()
	outputDefault, err := Terminal(comp, Options{NoColor: true})
	require.NoError(t, err)
	outputControl, err := Terminal(comp, Options{Detail: DetailControl, NoColor: true})
	require.NoError(t, err)
	assert.Equal(t, outputControl, outputDefault)
}

func TestTerminal_DefaultColorIsEnabled(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Contains(t, out, "\x1b[", "default should have color enabled")
}

func TestTerminal_DimColorForUnchanged(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: false})
	require.NoError(t, err)

	// Find the line containing V-1005 (unchanged)
	lines := strings.Split(out, "\n")
	var v1005Line string
	for _, line := range lines {
		if strings.Contains(line, "V-1005") {
			v1005Line = line
			break
		}
	}
	require.NotEmpty(t, v1005Line, "should find V-1005 line")
	assert.Contains(t, v1005Line, ansiDim, "unchanged line should use DIM color")
}

func TestTerminal_UnchangedNoStateLabel(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: true})
	require.NoError(t, err)

	// Find the line containing V-1005 (unchanged)
	lines := strings.Split(out, "\n")
	var v1005Line string
	for _, line := range lines {
		if strings.Contains(line, "V-1005") {
			v1005Line = line
			break
		}
	}
	require.NotEmpty(t, v1005Line, "should find V-1005 line")
	assert.NotContains(t, v1005Line, "(unchanged)", "unchanged should not have state label")
}

func TestTerminal_HandlesMissingTitleAndStatuses(t *testing.T) {
	comp := diff.HdfComparison{
		FormatVersion:  "1.0.0",
		ComparisonMode: diff.ModeTemporal,
		Sources:        []diff.Source{},
		Summary:        diff.ComparisonSummary{Updated: 1, Total: 1},
		RequirementDiffs: []diff.RequirementDiff{
			{
				ID:            "V-5001",
				State:         diff.StateUpdated,
				Title:         "",
				ChangeReasons: []diff.ChangeReason{diff.ReasonImpactChanged},
				FieldChanges: []diff.FieldChange{
					{Op: diff.OpAdd, Path: "tags.newTag", NewValue: "val"},
					{Op: diff.OpRemove, Path: "tags.oldTag", OldValue: "val"},
				},
			},
		},
		BaselineDiffs: []diff.BaselineDiff{},
	}
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: true})
	require.NoError(t, err)
	assert.Contains(t, out, "V-5001")
	assert.Contains(t, out, "(updated)")
	assert.Contains(t, out, "+tags.newTag")
	assert.Contains(t, out, "-tags.oldTag")
}

func TestTerminal_DateRangeDisplay(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailControl, NoColor: true})
	require.NoError(t, err)
	assert.Contains(t, out, "2026-03-01")
	assert.Contains(t, out, "2026-03-14")
}

func TestTerminal_MissingTimestampsOmitDateRange(t *testing.T) {
	comp := testFixture()
	comp.Sources = []diff.Source{
		{Role: diff.RoleOld, Label: "Old evaluation"},
		{Role: diff.RoleNew, Label: "New evaluation"},
	}
	out, err := Terminal(comp, Options{Detail: DetailSummary, NoColor: true})
	require.NoError(t, err)
	assert.Contains(t, out, "HDF Comparison: temporal")
	// Should not contain date parenthetical
	assert.NotContains(t, out, "(20")
}

func TestTerminal_GoldenRoleForBaselineMode(t *testing.T) {
	comp := testFixture()
	comp.ComparisonMode = diff.ModeBaseline
	comp.Sources = []diff.Source{
		{Role: diff.RoleGolden, Label: "Golden baseline", AssessmentTimestamp: "2024-01-01T00:00:00Z"},
		{Role: diff.RoleNew, Label: "Current scan", AssessmentTimestamp: "2024-02-01T00:00:00Z"},
	}
	out, err := Terminal(comp, Options{Detail: DetailSummary, NoColor: true})
	require.NoError(t, err)
	assert.Contains(t, out, "baseline")
	assert.Contains(t, out, "2024-01-01")
}

func TestTerminal_ReferenceSystemRolesForFleetMode(t *testing.T) {
	comp := testFixture()
	comp.ComparisonMode = diff.ModeFleet
	comp.Sources = []diff.Source{
		{Role: diff.RoleReference, Label: "Reference", AssessmentTimestamp: "2024-01-01T00:00:00Z"},
		{Role: diff.RoleSystem, Label: "System 1", AssessmentTimestamp: "2024-02-01T00:00:00Z"},
	}
	out, err := Terminal(comp, Options{Detail: DetailSummary, NoColor: true})
	require.NoError(t, err)
	assert.Contains(t, out, "fleet")
	assert.Contains(t, out, "2024-01-01")
	assert.Contains(t, out, "2024-02-01")
}

func TestTerminal_UpdatedRequirementShowsTilde(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: true})
	require.NoError(t, err)
	// V-1006 is updated
	assert.Regexp(t, `~\s+V-1006`, out)
}

func TestTerminal_FullModeShowsFieldChanges(t *testing.T) {
	comp := fieldChangeFixture()
	out, err := Terminal(comp, Options{Detail: DetailFull, NoColor: true})
	require.NoError(t, err)
	assert.Contains(t, out, "+tags.newTag")
	assert.Contains(t, out, "-tags.oldTag")
}

func TestTerminal_FilterStatesReducesOutput(t *testing.T) {
	comp := testFixture()
	out, err := Terminal(comp, Options{
		Detail:       DetailFull,
		NoColor:      true,
		FilterStates: []diff.RequirementState{diff.StateFixed},
	})
	require.NoError(t, err)
	assert.Contains(t, out, "V-1001")
	assert.NotContains(t, out, "V-1002")
	assert.NotContains(t, out, "V-1003")
}

// ─── CSV: edge cases ────────────────────────────────────────────────────────

func TestCSV_DefaultIsControlDetail(t *testing.T) {
	comp := testFixture()
	outputDefault, err := CSV(comp, Options{})
	require.NoError(t, err)
	outputControl, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Equal(t, outputControl, outputDefault)
}

func TestCSV_IncludesAllRequirementIDs(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	for _, req := range comp.RequirementDiffs {
		assert.Contains(t, out, req.ID, "CSV should include requirement %s", req.ID)
	}
}

// csvTitleEscapeFixture builds a single-diff comparison for testing CSV title escaping.
func csvTitleEscapeFixture(id string, state diff.RequirementState, title string) diff.HdfComparison {
	comp := testFixture()
	comp.RequirementDiffs = []diff.RequirementDiff{
		{
			ID:            id,
			State:         state,
			Title:         title,
			ChangeReasons: []diff.ChangeReason{},
			FieldChanges:  []diff.FieldChange{},
		},
	}
	return comp
}

// csvAssertTitleRoundTrips verifies a title survives CSV encoding and decoding.
func csvAssertTitleRoundTrips(t *testing.T, id, expectedTitle, rawCSV string) {
	t.Helper()
	reader := csv.NewReader(strings.NewReader(rawCSV))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	found := false
	for _, row := range records {
		if row[0] == id {
			assert.Equal(t, expectedTitle, row[1])
			found = true
		}
	}
	assert.True(t, found, "should find %s row", id)
}

func TestCSV_DoubleQuoteEscaping(t *testing.T) {
	comp := csvTitleEscapeFixture("V-6001", diff.StateFixed, `Ensure "root" login disabled`)
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	// RFC 4180: double quotes are escaped by doubling them
	assert.Contains(t, out, `"Ensure ""root"" login disabled"`)
	csvAssertTitleRoundTrips(t, "V-6001", `Ensure "root" login disabled`, out)
}

func TestCSV_NewlineEscaping(t *testing.T) {
	comp := csvTitleEscapeFixture("V-6002", diff.StateNew, "Line one\nLine two")
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)
	assert.Contains(t, out, "Line one\nLine two")
	csvAssertTitleRoundTrips(t, "V-6002", "Line one\nLine two", out)
}

func TestCSV_AddRemoveFieldChangeOps(t *testing.T) {
	comp := fieldChangeFixture()
	out, err := CSV(comp, Options{Detail: DetailFull})
	require.NoError(t, err)
	assert.Contains(t, out, "+tags.newTag")
	assert.Contains(t, out, "-tags.oldTag")
	assert.Contains(t, out, "impact:")
}

func TestCSV_MissingTitle(t *testing.T) {
	comp := testFixture()
	comp.RequirementDiffs = []diff.RequirementDiff{
		{
			ID:            "V-6003",
			State:         diff.StateFixed,
			Title:         "",
			ChangeReasons: []diff.ChangeReason{},
			FieldChanges:  []diff.FieldChange{},
		},
	}
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	// header + 1 data row
	assert.Equal(t, 2, len(records))
	// Title should be empty string
	assert.Equal(t, "", records[1][1])
}

func TestCSV_SummaryDetailOmitsFieldChanges(t *testing.T) {
	// Summary detail for CSV should still work but without field changes
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)

	lines := strings.Split(out, "\n")
	require.NotEmpty(t, lines)
	// Summary mode should not have "Field Changes" column
	assert.NotContains(t, lines[0], "Field Changes")
}

func TestCSV_FilterStates_MultipleStates(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{
		Detail:       DetailControl,
		FilterStates: []diff.RequirementState{diff.StateFixed, diff.StateNew},
	})
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	// header + 2 rows (fixed + new)
	assert.Equal(t, 3, len(records))
}

func TestCSV_ImpactColumnsPopulated(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// Find V-1006 which has old/new impact
	for _, row := range records {
		if row[0] == "V-1006" {
			assert.Equal(t, "0.7", row[5]) // Old Impact
			assert.Equal(t, "0.5", row[6]) // New Impact
		}
	}
}

func TestCSV_EmptyImpactForNilValues(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// V-1001 has no impact values
	for _, row := range records {
		if row[0] == "V-1001" {
			assert.Equal(t, "", row[5]) // Old Impact should be empty
			assert.Equal(t, "", row[6]) // New Impact should be empty
		}
	}
}

// ─── Filter: edge cases ─────────────────────────────────────────────────────

func TestFilterRequirements_EmptyStatesArrayReturnsAll(t *testing.T) {
	comp := testFixture()
	filtered := filterRequirements(comp.RequirementDiffs, Options{
		FilterStates: []diff.RequirementState{},
	})
	assert.Equal(t, len(comp.RequirementDiffs), len(filtered))
}

func TestFilterRequirements_NoMatchReturnsEmpty(t *testing.T) {
	comp := testFixture()
	filtered := filterRequirements(comp.RequirementDiffs, Options{
		FilterStates: []diff.RequirementState{"nonexistent"},
	})
	assert.Empty(t, filtered)
}

func TestFilterRequirements_AllStatesReturnsAll(t *testing.T) {
	comp := testFixture()
	filtered := filterRequirements(comp.RequirementDiffs, Options{
		FilterStates: []diff.RequirementState{
			diff.StateFixed,
			diff.StateRegressed,
			diff.StateNew,
			diff.StateAbsent,
			diff.StateUnchanged,
			diff.StateUpdated,
		},
	})
	assert.Equal(t, len(comp.RequirementDiffs), len(filtered))
}

func TestFilterRequirements_PreservesOrder(t *testing.T) {
	comp := testFixture()
	filtered := filterRequirements(comp.RequirementDiffs, Options{
		FilterStates: []diff.RequirementState{diff.StateFixed, diff.StateNew},
	})
	require.Equal(t, 2, len(filtered))
	// V-1001 (fixed) comes before V-1003 (new) in the original fixture
	assert.Equal(t, "V-1001", filtered[0].ID)
	assert.Equal(t, "V-1003", filtered[1].ID)
}

func TestFilterRequirements_EmptyDiffsReturnsEmpty(t *testing.T) {
	filtered := filterRequirements([]diff.RequirementDiff{}, Options{
		FilterStates: []diff.RequirementState{diff.StateFixed},
	})
	assert.Empty(t, filtered)
}

func TestFilterRequirements_NilDiffsReturnsEmpty(t *testing.T) {
	filtered := filterRequirements(nil, Options{
		FilterStates: []diff.RequirementState{diff.StateFixed},
	})
	assert.Empty(t, filtered)
}

// ─── Render helpers: formatFieldChangesWithArrow ────────────────────────────

func TestFormatFieldChanges_EmptyReturnsEmpty(t *testing.T) {
	result := formatFieldChangesWithArrow(nil, "->")
	assert.Equal(t, "", result)
}

func TestFormatFieldChanges_AddOp(t *testing.T) {
	changes := []diff.FieldChange{
		{Op: diff.OpAdd, Path: "tags.newTag", NewValue: "added"},
	}
	result := formatFieldChangesWithArrow(changes, "->")
	assert.Contains(t, result, "+tags.newTag")
	assert.Contains(t, result, "added")
}

func TestFormatFieldChanges_RemoveOp(t *testing.T) {
	changes := []diff.FieldChange{
		{Op: diff.OpRemove, Path: "tags.oldTag", OldValue: "removed"},
	}
	result := formatFieldChangesWithArrow(changes, "->")
	assert.Contains(t, result, "-tags.oldTag")
	assert.Contains(t, result, "removed")
}

func TestFormatFieldChanges_ReplaceOp(t *testing.T) {
	changes := []diff.FieldChange{
		{Op: diff.OpReplace, Path: "impact", OldValue: 0.3, NewValue: 0.7},
	}
	result := formatFieldChangesWithArrow(changes, "->")
	assert.Contains(t, result, "impact:")
	assert.Contains(t, result, "0.3")
	assert.Contains(t, result, "0.7")
	assert.Contains(t, result, "->")
}

func TestFormatFieldChanges_MultipleJoinedWithSemicolon(t *testing.T) {
	changes := []diff.FieldChange{
		{Op: diff.OpAdd, Path: "a", NewValue: "x"},
		{Op: diff.OpRemove, Path: "b", OldValue: "y"},
	}
	result := formatFieldChangesWithArrow(changes, "->")
	assert.Contains(t, result, "; ")
}

func TestFormatFieldChanges_NilValues(t *testing.T) {
	changes := []diff.FieldChange{
		{Op: diff.OpAdd, Path: "tags.new", NewValue: nil},
	}
	result := formatFieldChangesWithArrow(changes, "->")
	assert.Contains(t, result, "null")
}

func TestFormatFieldChanges_UnicodeArrow(t *testing.T) {
	changes := []diff.FieldChange{
		{Op: diff.OpReplace, Path: "title", OldValue: "old", NewValue: "new"},
	}
	result := formatFieldChangesWithArrow(changes, "\u2192")
	assert.Contains(t, result, "\u2192")
}

// ─── Render helpers: jsonValue ──────────────────────────────────────────────

func TestJsonValue_Nil(t *testing.T) {
	assert.Equal(t, "null", jsonValue(nil))
}

func TestJsonValue_String(t *testing.T) {
	assert.Equal(t, `"hello"`, jsonValue("hello"))
}

func TestJsonValue_Number(t *testing.T) {
	assert.Equal(t, "42", jsonValue(42))
}

func TestJsonValue_Float(t *testing.T) {
	assert.Equal(t, "0.7", jsonValue(0.7))
}

func TestJsonValue_Bool(t *testing.T) {
	assert.Equal(t, "true", jsonValue(true))
}

// ─── Render helpers: effectiveDetail ────────────────────────────────────────

func TestEffectiveDetail_DefaultIsControl(t *testing.T) {
	opts := Options{}
	assert.Equal(t, DetailControl, opts.effectiveDetail())
}

func TestEffectiveDetail_ExplicitSummary(t *testing.T) {
	opts := Options{Detail: DetailSummary}
	assert.Equal(t, DetailSummary, opts.effectiveDetail())
}

func TestEffectiveDetail_ExplicitFull(t *testing.T) {
	opts := Options{Detail: DetailFull}
	assert.Equal(t, DetailFull, opts.effectiveDetail())
}

// ─── Terminal: symbolAndColor ───────────────────────────────────────────────

func TestSymbolAndColor_FixedGreen(t *testing.T) {
	sym, colorFn := symbolAndColor(diff.StateFixed, true)
	assert.Equal(t, "+", sym)
	colored := colorFn("test")
	assert.Contains(t, colored, ansiGreen)
	assert.Contains(t, colored, ansiReset)
}

func TestSymbolAndColor_RegressedRed(t *testing.T) {
	sym, colorFn := symbolAndColor(diff.StateRegressed, true)
	assert.Equal(t, "-", sym)
	colored := colorFn("test")
	assert.Contains(t, colored, ansiRed)
}

func TestSymbolAndColor_NewGreen(t *testing.T) {
	sym, _ := symbolAndColor(diff.StateNew, true)
	assert.Equal(t, "+", sym)
}

func TestSymbolAndColor_AbsentRed(t *testing.T) {
	sym, _ := symbolAndColor(diff.StateAbsent, true)
	assert.Equal(t, "-", sym)
}

func TestSymbolAndColor_UpdatedYellow(t *testing.T) {
	sym, colorFn := symbolAndColor(diff.StateUpdated, true)
	assert.Equal(t, "~", sym)
	colored := colorFn("test")
	assert.Contains(t, colored, ansiYellow)
}

func TestSymbolAndColor_UnchangedDim(t *testing.T) {
	sym, colorFn := symbolAndColor(diff.StateUnchanged, true)
	assert.Equal(t, " ", sym)
	colored := colorFn("test")
	assert.Contains(t, colored, ansiDim)
}

func TestSymbolAndColor_NoColorIdentity(t *testing.T) {
	_, colorFn := symbolAndColor(diff.StateFixed, false)
	assert.Equal(t, "test", colorFn("test"))
}

func TestSymbolAndColor_UnknownStateDim(t *testing.T) {
	sym, colorFn := symbolAndColor("unknown_state", true)
	assert.Equal(t, " ", sym)
	colored := colorFn("test")
	assert.Contains(t, colored, ansiDim)
}

// ─── Terminal: formatStatusTransition ───────────────────────────────────────

func TestFormatStatusTransition_NewState(t *testing.T) {
	req := diff.RequirementDiff{State: diff.StateNew}
	assert.Equal(t, "(new)", formatStatusTransition(req))
}

func TestFormatStatusTransition_AbsentState(t *testing.T) {
	req := diff.RequirementDiff{State: diff.StateAbsent}
	assert.Equal(t, "(absent)", formatStatusTransition(req))
}

func TestFormatStatusTransition_FixedWithStatuses(t *testing.T) {
	req := diff.RequirementDiff{
		State:              diff.StateFixed,
		OldEffectiveStatus: "failed",
		NewEffectiveStatus: "passed",
	}
	result := formatStatusTransition(req)
	assert.Contains(t, result, "failed")
	assert.Contains(t, result, "passed")
	assert.Contains(t, result, "(fixed)")
}

func TestFormatStatusTransition_UnchangedNoLabel(t *testing.T) {
	req := diff.RequirementDiff{
		State:              diff.StateUnchanged,
		OldEffectiveStatus: "passed",
		NewEffectiveStatus: "passed",
	}
	result := formatStatusTransition(req)
	assert.NotContains(t, result, "(unchanged)")
	assert.Contains(t, result, "passed")
}

func TestFormatStatusTransition_NoStatuses(t *testing.T) {
	req := diff.RequirementDiff{State: diff.StateUpdated}
	result := formatStatusTransition(req)
	assert.Contains(t, result, "(updated)")
}

// ─── Markdown: escapeMarkdownCell ───────────────────────────────────────────

func TestEscapeMarkdownCell_NoPipe(t *testing.T) {
	assert.Equal(t, "hello world", escapeMarkdownCell("hello world"))
}

func TestEscapeMarkdownCell_WithPipe(t *testing.T) {
	assert.Equal(t, "a&#124;b", escapeMarkdownCell("a|b"))
}

func TestEscapeMarkdownCell_MultiplePipes(t *testing.T) {
	assert.Equal(t, "a&#124;b&#124;c", escapeMarkdownCell("a|b|c"))
}

// ─── CSV: formatImpact ──────────────────────────────────────────────────────

func TestFormatImpact_Nil(t *testing.T) {
	assert.Equal(t, "", formatImpact(nil))
}

func TestFormatImpact_Value(t *testing.T) {
	v := 0.7
	assert.Equal(t, "0.7", formatImpact(&v))
}

func TestFormatImpact_Zero(t *testing.T) {
	v := 0.0
	assert.Equal(t, "0", formatImpact(&v))
}

func TestFormatImpact_One(t *testing.T) {
	v := 1.0
	assert.Equal(t, "1", formatImpact(&v))
}

// ─── CSV: summary detail mode ────────────────────────────────────────────────

func TestCSV_SummaryDetail_StillHasAllRows(t *testing.T) {
	comp := testFixture()
	out, err := CSV(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// Summary detail for CSV still outputs all rows (no field changes column)
	// 1 header + 6 data rows
	assert.Equal(t, 7, len(records))
	// No Field Changes column
	assert.Equal(t, 8, len(records[0])) // 8 columns without Field Changes
}

// ─── JSON: summary mode sanity checks ────────────────────────────────────────

func TestJSON_SummaryMode_DoesNotContainRequirementDiffs(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailSummary})
	require.NoError(t, err)

	assert.NotContains(t, out, "requirementDiffs")
	assert.NotContains(t, out, "baselineDiffs")
	assert.Contains(t, out, "formatVersion")
	assert.Contains(t, out, "comparisonMode")
	assert.Contains(t, out, "summary")
}

// ─── JSON: full detail with no filter ────────────────────────────────────────

func TestJSON_FullDetail_NoFilter_AllPresent(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{Detail: DetailFull})
	require.NoError(t, err)

	var parsed diff.HdfComparison
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	assert.Equal(t, 6, len(parsed.RequirementDiffs))
}

// ─── JSON: control detail with filter ────────────────────────────────────────

func TestJSON_ControlDetail_WithFilter(t *testing.T) {
	comp := testFixture()
	out, err := JSON(comp, Options{
		Detail:       DetailControl,
		FilterStates: []diff.RequirementState{diff.StateAbsent, diff.StateNew},
	})
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	diffs := parsed["requirementDiffs"].([]any)
	assert.Equal(t, 2, len(diffs))
	for _, d := range diffs {
		diffMap := d.(map[string]any)
		state := diffMap["state"].(string)
		assert.True(t, state == "absent" || state == "new",
			"expected absent or new, got %s", state)
	}
}

// ─── render: jsonValue edge case — unmarshalable value ────────────────────────

func TestJsonValue_Unmarshalable(t *testing.T) {
	ch := make(chan int)
	result := jsonValue(ch)
	// json.Marshal fails on channels; fallback uses fmt.Sprintf which
	// produces a hex address like "0x1234..." — just verify it's not "null"
	// and not empty (the error branch was exercised).
	assert.NotEqual(t, "null", result)
	assert.NotEmpty(t, result)
}

func TestJsonValue_Map(t *testing.T) {
	result := jsonValue(map[string]any{"key": "val"})
	assert.Contains(t, result, `"key"`)
	assert.Contains(t, result, `"val"`)
}

func TestJsonValue_Slice(t *testing.T) {
	result := jsonValue([]string{"a", "b"})
	assert.Contains(t, result, `"a"`)
	assert.Contains(t, result, `"b"`)
}

// ─── symbolAndColor: moved/split/merged states ──────────────────────────────

func TestSymbolAndColor_MovedDim(t *testing.T) {
	sym, colorFn := symbolAndColor(diff.StateMoved, true)
	assert.Equal(t, " ", sym)
	colored := colorFn("test")
	assert.Contains(t, colored, ansiDim)
}

func TestSymbolAndColor_SplitDim(t *testing.T) {
	sym, _ := symbolAndColor(diff.StateSplit, false)
	assert.Equal(t, " ", sym)
}

func TestSymbolAndColor_MergedDim(t *testing.T) {
	sym, colorFn := symbolAndColor(diff.StateMerged, true)
	assert.Equal(t, " ", sym)
	colored := colorFn("test")
	assert.Contains(t, colored, ansiDim)
}

// ─── CSV: formatChangeReasonsCSV edge cases ──────────────────────────────────

func TestFormatChangeReasonsCSV_Empty(t *testing.T) {
	result := formatChangeReasons([]diff.ChangeReason{})
	assert.Equal(t, "", result)
}

func TestFormatChangeReasonsCSV_Multiple(t *testing.T) {
	result := formatChangeReasons([]diff.ChangeReason{
		diff.ReasonResultChanged,
		diff.ReasonImpactChanged,
	})
	assert.Equal(t, "resultChanged, impactChanged", result)
}

// ─── Terminal: formatStatusTransition — updated with statuses ────────────────

func TestFormatStatusTransition_UpdatedWithStatuses(t *testing.T) {
	req := diff.RequirementDiff{
		State:              diff.StateUpdated,
		OldEffectiveStatus: "notReviewed",
		NewEffectiveStatus: "notApplicable",
	}
	result := formatStatusTransition(req)
	assert.Contains(t, result, "notReviewed")
	assert.Contains(t, result, "notApplicable")
	assert.Contains(t, result, "(updated)")
}

func TestFormatStatusTransition_UnchangedWithStatuses(t *testing.T) {
	req := diff.RequirementDiff{
		State:              diff.StateUnchanged,
		OldEffectiveStatus: "failed",
		NewEffectiveStatus: "failed",
	}
	result := formatStatusTransition(req)
	assert.Contains(t, result, "failed")
	assert.NotContains(t, result, "(unchanged)")
}

// ─── CSV: row with nil impacts ──────────────────────────────────────────────

func TestCSV_NilImpacts_EmptyString(t *testing.T) {
	comp := testFixture()
	comp.RequirementDiffs = []diff.RequirementDiff{
		{
			ID:            "V-9001",
			State:         diff.StateNew,
			Title:         "No Impact",
			OldImpact:     nil,
			NewImpact:     nil,
			ChangeReasons: []diff.ChangeReason{},
			FieldChanges:  []diff.FieldChange{},
		},
	}
	out, err := CSV(comp, Options{Detail: DetailControl})
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(out))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Equal(t, 2, len(records))
	assert.Equal(t, "", records[1][5]) // Old Impact
	assert.Equal(t, "", records[1][6]) // New Impact
}

// ─── formatFieldChangesWithArrow: all ops in sequence ────────────────────────

func TestFormatFieldChanges_AllOpsInSequence(t *testing.T) {
	changes := []diff.FieldChange{
		{Op: diff.OpAdd, Path: "new_field", NewValue: "added"},
		{Op: diff.OpRemove, Path: "old_field", OldValue: "removed"},
		{Op: diff.OpReplace, Path: "changed_field", OldValue: "old", NewValue: "new"},
	}
	result := formatFieldChangesWithArrow(changes, "=>")
	assert.Contains(t, result, "+new_field")
	assert.Contains(t, result, "-old_field")
	assert.Contains(t, result, "changed_field:")
	assert.Contains(t, result, "=>")
	// Three parts joined with "; "
	parts := strings.Split(result, "; ")
	assert.Equal(t, 3, len(parts))
}
