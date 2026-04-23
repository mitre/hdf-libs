// Package render provides formatters for HdfComparison documents.
//
// Supported output formats: JSON, Markdown, Terminal (ANSI), CSV.
// Each renderer respects the DetailLevel and filter options to control
// verbosity and focus on specific requirement states.
package render

import (
	"encoding/json"
	"fmt"
	"strings"

	diff "github.com/mitre/hdf-libs/hdf-diff/go"
)

// DetailLevel controls how much detail renderers show.
type DetailLevel string

const (
	// DetailSummary shows only aggregate counts.
	DetailSummary DetailLevel = "summary"
	// DetailControl shows per-requirement tables without full snapshots.
	DetailControl DetailLevel = "control"
	// DetailFull shows all available information including field changes.
	DetailFull DetailLevel = "full"
)

// Options configures rendering behavior.
type Options struct {
	Detail       DetailLevel
	FilterStates []diff.RequirementState
	NoColor      bool
}

// effectiveDetail returns the detail level, defaulting to DetailControl.
func (o Options) effectiveDetail() DetailLevel {
	if o.Detail == "" {
		return DetailControl
	}
	return o.Detail
}

// Render dispatches to the appropriate renderer based on format.
func Render(comparison diff.HdfComparison, format string, opts Options) (string, error) {
	switch format {
	case "json":
		return JSON(comparison, opts)
	case "markdown":
		return Markdown(comparison, opts)
	case "terminal":
		return Terminal(comparison, opts)
	case "csv":
		return CSV(comparison, opts)
	default:
		return "", fmt.Errorf("unknown format: %s", format)
	}
}

// filterRequirements returns only the diffs whose state matches opts.FilterStates.
// If FilterStates is empty, all diffs are returned.
func filterRequirements(diffs []diff.RequirementDiff, opts Options) []diff.RequirementDiff {
	if len(opts.FilterStates) == 0 {
		return diffs
	}

	allowed := make(map[diff.RequirementState]bool, len(opts.FilterStates))
	for _, s := range opts.FilterStates {
		allowed[s] = true
	}

	var filtered []diff.RequirementDiff
	for _, d := range diffs {
		if allowed[d.State] {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

// formatFieldChangesWithArrow formats field changes as a human-readable string,
// using the specified arrow string for replace operations.
func formatFieldChangesWithArrow(changes []diff.FieldChange, arrow string) string {
	if len(changes) == 0 {
		return ""
	}
	parts := make([]string, len(changes))
	for i, fc := range changes {
		switch fc.Op {
		case diff.OpAdd:
			parts[i] = fmt.Sprintf("+%s: %s", fc.Path, jsonValue(fc.NewValue))
		case diff.OpRemove:
			parts[i] = fmt.Sprintf("-%s: %s", fc.Path, jsonValue(fc.OldValue))
		case diff.OpReplace:
			parts[i] = fmt.Sprintf("%s: %s %s %s", fc.Path, jsonValue(fc.OldValue), arrow, jsonValue(fc.NewValue))
		}
	}
	return strings.Join(parts, "; ")
}

// formatChangeReasons joins change reasons with commas.
func formatChangeReasons(reasons []diff.ChangeReason) string {
	parts := make([]string, len(reasons))
	for i, r := range reasons {
		parts[i] = string(r)
	}
	return strings.Join(parts, ", ")
}

// jsonValue marshals a value to its JSON representation.
func jsonValue(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
