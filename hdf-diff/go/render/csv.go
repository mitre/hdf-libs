package render

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	diff "github.com/mitre/hdf-libs/hdf-diff/go"
)

// CSV renders an HdfComparison as a CSV string.
//
// Columns: ID, Title, State, Old Status, New Status, Impact (Old), Impact (New), Change Reasons.
// When detail is DetailFull, an additional "Field Changes" column is included.
// Uses encoding/csv for proper RFC 4180 escaping.
func CSV(comparison diff.HdfComparison, opts Options) (string, error) {
	detail := opts.effectiveDetail()
	filtered := filterRequirements(comparison.RequirementDiffs, opts)

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Header
	header := []string{
		"ID", "Title", "State", "Old Status", "New Status",
		"Impact (Old)", "Impact (New)", "Change Reasons",
	}
	if detail == DetailFull {
		header = append(header, "Field Changes")
	}
	if err := w.Write(header); err != nil {
		return "", fmt.Errorf("writing CSV header: %w", err)
	}

	// Data rows
	for _, req := range filtered {
		row := []string{
			sanitizeCSVCell(req.ID),
			sanitizeCSVCell(req.Title),
			string(req.State),
			req.OldEffectiveStatus,
			req.NewEffectiveStatus,
			formatImpact(req.OldImpact),
			formatImpact(req.NewImpact),
			sanitizeCSVCell(formatChangeReasons(req.ChangeReasons)),
		}
		if detail == DetailFull {
			row = append(row, sanitizeCSVCell(formatFieldChangesWithArrow(req.FieldChanges, "->")))
		}
		if err := w.Write(row); err != nil {
			return "", fmt.Errorf("writing CSV row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("flushing CSV: %w", err)
	}

	// Trim trailing newline added by csv.Writer
	return strings.TrimRight(buf.String(), "\n"), nil
}

// sanitizeCSVCell prevents spreadsheet formula injection by prepending a single
// quote when the cell starts with a formula trigger character.
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '|', '%':
		return "'" + s
	}
	return s
}

// formatImpact formats an optional impact value for CSV output.
func formatImpact(impact *float64) string {
	if impact == nil {
		return ""
	}
	return fmt.Sprintf("%g", *impact)
}
