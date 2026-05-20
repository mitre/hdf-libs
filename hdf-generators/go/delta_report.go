package generators

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DeltaJsonReport is the JSON report payload (SAF CLI-compatible).
type DeltaJsonReport struct {
	Links []LinkRecord `json:"links"`
}

// GenerateDeltaJSON generates a structured JSON report from a delta result.
func GenerateDeltaJSON(result DeltaResult) ([]byte, error) {
	report := DeltaJsonReport{
		Links: result.LinkRecords,
	}
	return json.MarshalIndent(report, "", "  ")
}

// formatMatchMethod returns a SAF CLI-compatible match method description.
func formatMatchMethod(lr LinkRecord) string {
	confidencePct := fmt.Sprintf("%d%%", int(lr.Confidence*100))
	switch lr.MatchMethod {
	case "srgDeterministic":
		srg := lr.SRG
		if srg == "" {
			srg = "?"
		}
		return fmt.Sprintf("SRG deterministic (%s) [%s]", srg, lr.Relationship)
	case "srgCciTiebreak":
		return fmt.Sprintf("SRG block + CCI tiebreak (Jaccard=%s) [%s]", confidencePct, lr.Relationship)
	case "vendorFuzzyTitle":
		return fmt.Sprintf("Vendor fuzzy title (confidence=%s) [%s]", confidencePct, lr.Relationship)
	case "exactId":
		return fmt.Sprintf("Exact ID [%s]", lr.Relationship)
	case "cciMatch":
		return fmt.Sprintf("CCI match [%s]", lr.Relationship)
	case "fuzzyTitle":
		return fmt.Sprintf("Fuzzy title (confidence=%s) [%s]", confidencePct, lr.Relationship)
	case "none":
		return "No match"
	default:
		return fmt.Sprintf("%s [%s]", lr.MatchMethod, lr.Relationship)
	}
}

// GenerateDeltaMarkdown generates a Markdown report matching SAF CLI's format.
func GenerateDeltaMarkdown(result DeltaResult) string {
	var b strings.Builder
	stats := result.Statistics

	// Mapping results
	if len(result.LinkRecords) > 0 {
		b.WriteString("Mapping Results ===========================================================================\n")
		b.WriteString("\tOld Control -> New Control\n")
		for _, lr := range result.LinkRecords {
			if lr.Relationship != "no-match" && lr.OldID != "" {
				fmt.Fprintf(&b, "\t   %s -> %s\n", lr.OldID, lr.NewID)
			}
		}
		fmt.Fprintf(&b, "Total Mapped Controls:  %d\n\n", stats.TotalMappedControls)
	}

	// Control counts
	b.WriteString("Control Counts ===========================\n")
	fmt.Fprintf(&b, "Total Controls Available for Delta:  %d\n", stats.OldControlsLength)
	fmt.Fprintf(&b, "     Total Controls Found on XCCDF:  %d\n\n", stats.NewControlsLength)

	// Match statistics
	b.WriteString("Match Statistics =========================\n")
	fmt.Fprintf(&b, "                    Match Controls:  %d\n", stats.Match)
	fmt.Fprintf(&b, "        Possible Mismatch Controls:  %d\n", stats.PosMisMatch)
	fmt.Fprintf(&b, "            Related Match Controls:  %d\n", stats.DupMatch)
	fmt.Fprintf(&b, "                 No Match Controls:  %d\n\n", stats.NoMatch)

	// Statistics validation
	b.WriteString("Statistics Validation =============================================\n")
	totalMapped := stats.TotalMappedControls
	matchMappedValid := (stats.Match + stats.PosMisMatch + stats.DupMatch) == totalMapped
	processedValid := (totalMapped + stats.NoMatch) == stats.NewControlsLength
	fmt.Fprintf(&b, "Match + Mismatch + Related = Total Mapped Controls:  (%d+%d+%d=%d) %t\n",
		stats.Match, stats.PosMisMatch, stats.DupMatch, totalMapped, matchMappedValid)
	fmt.Fprintf(&b, "  Total Processed = Total XCCDF Controls:  (%d+%d=%d) %t\n\n",
		totalMapped, stats.NoMatch, totalMapped+stats.NoMatch, processedValid)

	// Per-control match details
	if len(result.LinkRecords) > 0 {
		b.WriteString("Match Details =============================================================\n")
		for _, lr := range result.LinkRecords {
			if lr.OldID != "" {
				fmt.Fprintf(&b, "  %s --> %s\n", lr.OldID, lr.NewID)
				fmt.Fprintf(&b, "       Match method:  %s\n", formatMatchMethod(lr))
			} else {
				fmt.Fprintf(&b, "  (none) --> %s  [no match]\n", lr.NewID)
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}
