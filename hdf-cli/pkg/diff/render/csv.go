package render

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	types "github.com/mitre/hdf-cli/pkg/diff/types"
)

// CSV renders an HdfComparison as a CSV string.
//
// Columns: ID, Title, State, Old Status, New Status, Impact (Old), Impact (New), Change Reasons.
// When detail is DetailFull, an additional "Field Changes" column is included.
// Uses encoding/csv for proper RFC 4180 escaping.
func CSV(comparison types.HdfComparison, opts Options) (string, error) {
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
			req.ID,
			req.Title,
			string(req.State),
			req.OldEffectiveStatus,
			req.NewEffectiveStatus,
			formatImpact(req.OldImpact),
			formatImpact(req.NewImpact),
			formatChangeReasons(req.ChangeReasons),
		}
		if detail == DetailFull {
			row = append(row, formatFieldChangesWithArrow(req.FieldChanges, "->"))
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

// formatImpact formats an optional impact value for CSV output.
func formatImpact(impact *float64) string {
	if impact == nil {
		return ""
	}
	return fmt.Sprintf("%g", *impact)
}
