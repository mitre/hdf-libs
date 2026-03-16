package render

import (
	"fmt"
	"strings"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
)

// stateOrder defines the display order for requirement state sections.
var stateOrder = []types.RequirementState{
	types.StateFixed,
	types.StateRegressed,
	types.StateNew,
	types.StateAbsent,
	types.StateUpdated,
	types.StateUnchanged,
}

// Markdown renders an HdfComparison as a Markdown string.
//
//   - DetailSummary: summary table only
//   - DetailControl: summary + per-requirement tables by state
//   - DetailFull: summary + per-requirement tables with changeReasons and fieldChanges
func Markdown(comparison types.HdfComparison, opts Options) (string, error) {
	detail := opts.effectiveDetail()

	var sb strings.Builder

	renderSummaryTable(&sb, comparison)

	if detail == DetailSummary {
		return sb.String(), nil
	}

	filtered := filterRequirements(comparison.RequirementDiffs, opts)
	grouped := groupByState(filtered)

	// Determine which states to show
	statesToShow := stateOrder
	if len(opts.FilterStates) > 0 {
		allowed := make(map[types.RequirementState]bool, len(opts.FilterStates))
		for _, s := range opts.FilterStates {
			allowed[s] = true
		}
		var selected []types.RequirementState
		for _, s := range stateOrder {
			if allowed[s] {
				selected = append(selected, s)
			}
		}
		statesToShow = selected
	}

	for _, state := range statesToShow {
		sb.WriteString("\n")
		diffs := grouped[state]
		renderStateSection(&sb, state, diffs, detail)
	}

	return sb.String(), nil
}

// renderSummaryTable writes the markdown summary table.
func renderSummaryTable(sb *strings.Builder, comparison types.HdfComparison) {
	s := comparison.Summary
	sb.WriteString("## HDF Comparison Summary\n")
	sb.WriteString("\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	fmt.Fprintf(sb, "| Fixed | %d |\n", s.Fixed)
	fmt.Fprintf(sb, "| Regressed | %d |\n", s.Regressed)
	fmt.Fprintf(sb, "| New | %d |\n", s.New)
	fmt.Fprintf(sb, "| Absent | %d |\n", s.Absent)
	fmt.Fprintf(sb, "| Unchanged | %d |\n", s.Unchanged)
	fmt.Fprintf(sb, "| Updated | %d |\n", s.Updated)
	fmt.Fprintf(sb, "| **Total** | **%d** |", s.Total)
}

// groupByState groups requirement diffs by their state.
func groupByState(diffs []types.RequirementDiff) map[types.RequirementState][]types.RequirementDiff {
	groups := make(map[types.RequirementState][]types.RequirementDiff)
	for _, d := range diffs {
		groups[d.State] = append(groups[d.State], d)
	}
	return groups
}

// renderStateSection writes a markdown section for a single state group.
func renderStateSection(sb *strings.Builder, state types.RequirementState, diffs []types.RequirementDiff, detail DetailLevel) {
	label := strings.ToUpper(string(state)[:1]) + string(state)[1:]
	fmt.Fprintf(sb, "### %s (%d)\n", label, len(diffs))

	if len(diffs) == 0 {
		sb.WriteString("\n(none)")
		return
	}

	sb.WriteString("\n")

	if detail == DetailFull {
		sb.WriteString("| ID | Title | Old Status | New Status | Change Reasons | Field Changes |\n")
		sb.WriteString("|----|-------|------------|------------|----------------|---------------|\n")
		for _, req := range diffs {
			id := escapeMarkdownCell(req.ID)
			title := escapeMarkdownCell(req.Title)
			oldStatus := escapeMarkdownCell(req.OldEffectiveStatus)
			newStatus := escapeMarkdownCell(req.NewEffectiveStatus)
			reasons := escapeMarkdownCell(formatChangeReasons(req.ChangeReasons))
			fieldChanges := escapeMarkdownCell(formatFieldChangesWithArrow(req.FieldChanges, "->"))
			fmt.Fprintf(sb, "| %s | %s | %s | %s | %s | %s |\n", id, title, oldStatus, newStatus, reasons, fieldChanges)
		}
	} else {
		sb.WriteString("| ID | Title | Old Status | New Status |\n")
		sb.WriteString("|----|-------|------------|------------|\n")
		for _, req := range diffs {
			id := escapeMarkdownCell(req.ID)
			title := escapeMarkdownCell(req.Title)
			oldStatus := escapeMarkdownCell(req.OldEffectiveStatus)
			newStatus := escapeMarkdownCell(req.NewEffectiveStatus)
			fmt.Fprintf(sb, "| %s | %s | %s | %s |\n", id, title, oldStatus, newStatus)
		}
	}
}

// escapeMarkdownCell replaces pipe characters with HTML entities.
func escapeMarkdownCell(value string) string {
	return strings.ReplaceAll(value, "|", "&#124;")
}
