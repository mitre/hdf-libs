package render

import (
	"fmt"
	"strings"

	diff "github.com/mitre/hdf-diff/go"
)

// ANSI color codes.
const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
)

// Terminal renders an HdfComparison for terminal display with optional ANSI colors.
//
//   - DetailSummary: header + summary line only
//   - DetailControl: header + requirement list (excludes unchanged) + summary
//   - DetailFull: header + all requirements including unchanged with changeReasons/fieldChanges + summary
func Terminal(comparison diff.HdfComparison, opts Options) (string, error) {
	detail := opts.effectiveDetail()
	useColor := !opts.NoColor

	var sb strings.Builder

	// Header
	sb.WriteString(buildHeaderLine(comparison, useColor))
	sb.WriteString("\n")

	if detail == DetailSummary {
		sb.WriteString("\n")
		sb.WriteString(buildSummaryLine(comparison, useColor))
		return sb.String(), nil
	}

	sb.WriteString("\n")

	// Requirement lines
	filtered := filterRequirements(comparison.RequirementDiffs, opts)

	for _, req := range filtered {
		// In control mode, skip unchanged requirements
		if detail == DetailControl && req.State == diff.StateUnchanged {
			continue
		}
		sb.WriteString(renderRequirementLine(req, detail, useColor))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(buildSummaryLine(comparison, useColor))

	return sb.String(), nil
}

// symbolAndColor returns the terraform-style symbol and color wrapper for a state.
func symbolAndColor(state diff.RequirementState, useColor bool) (string, func(string) string) {
	identity := func(s string) string { return s }

	switch state {
	case diff.StateFixed, diff.StateNew:
		if useColor {
			return "+", func(s string) string { return ansiGreen + s + ansiReset }
		}
		return "+", identity
	case diff.StateRegressed, diff.StateAbsent:
		if useColor {
			return "-", func(s string) string { return ansiRed + s + ansiReset }
		}
		return "-", identity
	case diff.StateUpdated:
		if useColor {
			return "~", func(s string) string { return ansiYellow + s + ansiReset }
		}
		return "~", identity
	case diff.StateUnchanged, diff.StateMoved, diff.StateSplit, diff.StateMerged:
		if useColor {
			return " ", func(s string) string { return ansiDim + s + ansiReset }
		}
		return " ", identity
	default:
		if useColor {
			return " ", func(s string) string { return ansiDim + s + ansiReset }
		}
		return " ", identity
	}
}

// renderRequirementLine formats a single requirement for terminal display.
func renderRequirementLine(req diff.RequirementDiff, detail DetailLevel, useColor bool) string {
	symbol, colorFn := symbolAndColor(req.State, useColor)
	transition := formatStatusTransition(req)

	line := fmt.Sprintf("  %s %s  %s    %s", symbol, req.ID, req.Title, transition)

	if detail == DetailFull {
		if len(req.ChangeReasons) > 0 {
			reasons := make([]string, len(req.ChangeReasons))
			for i, r := range req.ChangeReasons {
				reasons[i] = string(r)
			}
			line += fmt.Sprintf("  [%s]", strings.Join(reasons, ", "))
		}
		fc := formatFieldChangesWithArrow(req.FieldChanges, "\u2192")
		if fc != "" {
			line += "  " + fc
		}
	}

	return colorFn(line)
}

// formatStatusTransition formats the status change portion of a requirement line.
func formatStatusTransition(req diff.RequirementDiff) string {
	if req.State == diff.StateNew {
		return "(new)"
	}
	if req.State == diff.StateAbsent {
		return "(absent)"
	}

	var parts []string

	if req.OldEffectiveStatus != "" && req.NewEffectiveStatus != "" {
		parts = append(parts, fmt.Sprintf("%s \u2192 %s", req.OldEffectiveStatus, req.NewEffectiveStatus))
	}

	if req.State != diff.StateUnchanged {
		parts = append(parts, fmt.Sprintf("(%s)", req.State))
	}

	return strings.Join(parts, "   ")
}

// buildHeaderLine builds the header for terminal output.
func buildHeaderLine(comparison diff.HdfComparison, useColor bool) string {
	header := fmt.Sprintf("HDF Comparison: %s", comparison.ComparisonMode)

	// Find old and new source timestamps
	var oldTimestamp, newTimestamp string
	for _, s := range comparison.Sources {
		switch s.Role {
		case diff.RoleOld, diff.RoleGolden, diff.RoleReference:
			if oldTimestamp == "" {
				oldTimestamp = s.AssessmentTimestamp
			}
		case diff.RoleNew, diff.RoleSystem:
			if newTimestamp == "" {
				newTimestamp = s.AssessmentTimestamp
			}
		}
	}

	if oldTimestamp != "" && newTimestamp != "" {
		oldDate := strings.SplitN(oldTimestamp, "T", 2)[0]
		newDate := strings.SplitN(newTimestamp, "T", 2)[0]
		header += fmt.Sprintf(" (%s \u2192 %s)", oldDate, newDate)
	}

	if useColor {
		return ansiBold + header + ansiReset
	}
	return header
}

// buildSummaryLine builds the summary line for terminal output.
func buildSummaryLine(comparison diff.HdfComparison, useColor bool) string {
	s := comparison.Summary
	line := fmt.Sprintf("Summary: %d fixed, %d regressed, %d new, %d absent, %d unchanged, %d updated (%d total)",
		s.Fixed, s.Regressed, s.New, s.Absent, s.Unchanged, s.Updated, s.Total)

	if useColor {
		return ansiBold + line + ansiReset
	}
	return line
}
