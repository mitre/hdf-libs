package cmd

import (
	"encoding/json"
	"fmt"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/spf13/cobra"
)

// NewStatsCmd creates a new stats command with fresh state.
func NewStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats <file>",
		Short: "Display assessment statistics from an HDF file",
		Long: `Display statistics from an HDF results file including:
- Total controls/requirements
- Pass/fail/error/not_applicable/not_reviewed counts
- Duration

Examples:
  hdf stats results.json
  hdf stats results.json --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: runStats,
	}
}

type controlStats struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	NotApplicable int `json:"not_applicable"`
	NotReviewed   int `json:"not_reviewed"`
	Error         int `json:"error"`
	Skipped       int `json:"skipped"`
}

func runStats(_ *cobra.Command, args []string) error {
	var filename string
	if len(args) == 0 || args[0] == "-" {
		filename = "-"
	} else {
		filename = args[0]
	}

	data, err := readInputFile(filename)
	if err != nil {
		printError(err.Error())
		return err
	}

	results, err := parseHDFResults(data)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse HDF file: %v", err))
		return err
	}

	// Calculate stats from controls
	stats := calculateStats(results)

	if jsonOutput {
		return outputStatsJSON(results, stats)
	}

	return outputStatsHuman(results, stats)
}

func calculateStats(results hdf.HdfResults) controlStats {
	stats := controlStats{}

	for _, baseline := range results.Baselines {
		for _, control := range baseline.Requirements {
			stats.Total++

			// Determine status from results
			status := determineControlStatus(control)
			switch status {
			case StatusPassed:
				stats.Passed++
			case StatusFailed:
				stats.Failed++
			case StatusNotApplicable:
				stats.NotApplicable++
			case StatusNotReviewed:
				stats.NotReviewed++
			case StatusError:
				stats.Error++
			case StatusSkipped:
				stats.Skipped++
			}
		}
	}

	return stats
}

func determineControlStatus(control hdf.EvaluatedRequirement) string {
	// If effectiveStatus is set, use the shared schema→display mapping
	if control.EffectiveStatus != nil {
		return SchemaStatusToDisplay(*control.EffectiveStatus)
	}

	// Otherwise, derive from results
	if len(control.Results) == 0 {
		// No results - check impact for not_applicable
		if control.Impact == 0 {
			return StatusNotApplicable
		}
		return StatusNotReviewed
	}

	// Apply InSpec precedence: error > failed > passed > notApplicable > notReviewed
	// Fail-fast on error (highest precedence). Collect flags for the rest.
	hasFailed := false
	hasPassed := false
	hasNotApplicable := false

	for _, result := range control.Results {
		if result.Status == nil {
			continue
		}
		switch *result.Status {
		case hdf.Error:
			return StatusError // highest precedence — no need to scan further
		case hdf.Failed:
			hasFailed = true
		case hdf.Passed:
			hasPassed = true
		case hdf.NotApplicable:
			hasNotApplicable = true
		case hdf.NotReviewed:
			// lowest precedence — only returned if nothing else matches
		}
	}

	if hasFailed {
		return StatusFailed
	}
	if hasPassed {
		return StatusPassed
	}
	if hasNotApplicable {
		return StatusNotApplicable
	}

	return StatusNotReviewed
}

func outputStatsJSON(results hdf.HdfResults, stats controlStats) error {
	output := map[string]interface{}{
		"controls": stats,
	}

	if results.Statistics.Duration != nil {
		output["duration_seconds"] = *results.Statistics.Duration
	}

	// Include baseline breakdown
	baselines := make([]map[string]interface{}, 0)
	for _, b := range results.Baselines {
		bStats := controlStats{}
		for _, c := range b.Requirements {
			bStats.Total++
			status := determineControlStatus(c)
			switch status {
			case StatusPassed:
				bStats.Passed++
			case StatusFailed:
				bStats.Failed++
			case StatusNotApplicable:
				bStats.NotApplicable++
			case StatusNotReviewed:
				bStats.NotReviewed++
			case StatusError:
				bStats.Error++
			case StatusSkipped:
				bStats.Skipped++
			}
		}
		baselines = append(baselines, map[string]interface{}{
			"name":         b.Name,
			"requirements": bStats,
		})
	}
	output["baselines"] = baselines

	jsonOut, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonOut))
	return nil
}

func outputStatsHuman(results hdf.HdfResults, stats controlStats) error {
	fmt.Println("Assessment Statistics")
	fmt.Println("=====================")
	fmt.Println()

	if results.Statistics.Duration != nil {
		fmt.Printf("Duration: %.2f seconds\n\n", *results.Statistics.Duration)
	}

	fmt.Printf("Total Controls: %d\n", stats.Total)
	fmt.Println()

	// Calculate percentages
	if stats.Total > 0 {
		fmt.Println("Results:")
		printStatLine("Passed", stats.Passed, stats.Total, "✓")
		printStatLine("Failed", stats.Failed, stats.Total, "✗")
		printStatLine("Not Applicable", stats.NotApplicable, stats.Total, "○")
		printStatLine("Not Reviewed", stats.NotReviewed, stats.Total, "?")
		if stats.Error > 0 {
			printStatLine("Error", stats.Error, stats.Total, "!")
		}
		if stats.Skipped > 0 {
			printStatLine("Skipped (deprecated)", stats.Skipped, stats.Total, "-")
		}
	}

	// Per-baseline breakdown
	if len(results.Baselines) > 1 {
		fmt.Println()
		fmt.Println("By Baseline:")
		for _, b := range results.Baselines {
			passed := 0
			for _, c := range b.Requirements {
				status := determineControlStatus(c)
				if status == StatusPassed {
					passed++
				}
			}
			fmt.Printf("  %s: %d/%d passed\n", b.Name, passed, len(b.Requirements))
		}
	}

	return nil
}

func printStatLine(label string, count, total int, symbol string) {
	pct := float64(count) / float64(total) * 100
	fmt.Printf("  %s %-14s %4d (%5.1f%%)\n", symbol, label+":", count, pct)
}
