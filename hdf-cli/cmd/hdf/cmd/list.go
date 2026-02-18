package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/spf13/cobra"
)

// Global flag variables for list command (used by runList).
var (
	statusFilter string
	showAll      bool
)

// NewListCmd creates a new list command with fresh state.
func NewListCmd() *cobra.Command { //nolint:dupl // Cobra command setup; flags and args differ per command
	// Local flag variables for this command instance
	var (
		localStatusFilter string
		localShowAll      bool
	)

	cmd := &cobra.Command{
		Use:   "list <what> <file>",
		Short: "List controls, profiles, or targets from an HDF file",
		Long: `List items from an HDF results file.

Available list types:
  controls   List all controls/requirements with their status
  profiles   List all profiles/baselines
  targets    List all scan targets

Examples:
  hdf list controls results.json
  hdf list controls results.json --status failed
  hdf list profiles results.json
  hdf list targets results.json --json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Sync local flags to global variables for runList
			statusFilter = localStatusFilter
			showAll = localShowAll
			return runList(cmd, args)
		},
	}

	cmd.Flags().StringVarP(&localStatusFilter, "status", "s", "", "Filter by status (passed, failed, error, not_applicable, not_reviewed)")
	cmd.Flags().BoolVarP(&localShowAll, "all", "a", false, "Show all details")

	return cmd
}

func runList(_ *cobra.Command, args []string) error {
	listType := strings.ToLower(args[0])
	filename := args[1]

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

	switch listType {
	case "controls", "control", "c":
		return listControls(results)
	case "profiles", "profile", "p":
		return listProfiles(results)
	case "targets", "target", "t":
		return listTargets(results)
	default:
		printError(fmt.Sprintf("Unknown list type: %s", listType),
			"Valid types: controls, profiles, targets")
		return fmt.Errorf("unknown list type: %s", listType)
	}
}

type controlInfo struct {
	ID      string  `json:"id"`
	Title   string  `json:"title,omitempty"`
	Status  string  `json:"status"`
	Impact  float64 `json:"impact"`
	Profile string  `json:"profile"`
}

func listControls(results hdf.HdfResults) error {
	controls := buildControlList(results)

	if jsonOutput {
		return printControlsJSON(controls)
	}

	fmt.Printf("Controls: %d\n\n", len(controls))

	if statusFilter == "" && !showAll {
		printControlsSummary(controls)
	} else {
		printControlsFlat(controls)
	}

	return nil
}

func buildControlList(results hdf.HdfResults) []controlInfo {
	var controls []controlInfo

	for _, baseline := range results.Baselines {
		for _, c := range baseline.Requirements {
			status := determineControlStatus(c)

			if statusFilter != "" && status != statusFilter {
				continue
			}

			title := ""
			if c.Title != nil {
				title = *c.Title
			}

			controls = append(controls, controlInfo{
				ID:      c.ID,
				Title:   title,
				Status:  status,
				Impact:  c.Impact,
				Profile: baseline.Name,
			})
		}
	}

	return controls
}

func printControlsJSON(controls []controlInfo) error {
	output, _ := json.MarshalIndent(controls, "", "  ")
	fmt.Println(string(output))
	return nil
}

func printControlsSummary(controls []controlInfo) {
	byStatus := make(map[string][]controlInfo)
	for _, c := range controls {
		byStatus[c.Status] = append(byStatus[c.Status], c)
	}

	for _, status := range []string{StatusFailed, StatusError, StatusPassed, StatusNotApplicable, StatusNotReviewed} {
		if len(byStatus[status]) == 0 {
			continue
		}
		fmt.Printf("%s (%d):\n", strings.ToUpper(status), len(byStatus[status]))
		for _, c := range byStatus[status] {
			title := truncateTitle(c.Title, 50)
			fmt.Printf("  %-15s %s\n", sanitizeOutput(c.ID), title)
		}
		fmt.Println()
	}
}

func printControlsFlat(controls []controlInfo) {
	for _, c := range controls {
		statusSymbol := statusToSymbol(c.Status)
		title := truncateTitle(c.Title, 60)
		fmt.Printf("%s %-15s %s\n", statusSymbol, sanitizeOutput(c.ID), title)
	}
}

func truncateTitle(title string, maxLen int) string {
	title = sanitizeOutput(title)
	if len(title) > maxLen {
		title = title[:maxLen-3] + "..."
	}
	if title == "" {
		title = noTitlePlaceholder
	}
	return title
}

func listProfiles(results hdf.HdfResults) error {
	type baselineInfo struct {
		Name             string `json:"name"`
		Title            string `json:"title,omitempty"`
		Version          string `json:"version,omitempty"`
		RequirementCount int    `json:"requirement_count"`
		Status           string `json:"status,omitempty"`
	}

	var baselines []baselineInfo

	for _, b := range results.Baselines {
		info := baselineInfo{
			Name:             b.Name,
			RequirementCount: len(b.Requirements),
		}
		if b.Title != nil {
			info.Title = *b.Title
		}
		if b.Version != nil {
			info.Version = *b.Version
		}
		if b.Status != nil {
			info.Status = *b.Status
		}
		baselines = append(baselines, info)
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(baselines, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	fmt.Printf("Baselines: %d\n\n", len(baselines))
	for _, b := range baselines {
		name := sanitizeOutput(b.Name)
		if b.Title != "" && b.Title != b.Name {
			name = fmt.Sprintf("%s (%s)", sanitizeOutput(b.Title), sanitizeOutput(b.Name))
		}
		version := ""
		if b.Version != "" {
			version = fmt.Sprintf(" v%s", sanitizeOutput(b.Version))
		}
		fmt.Printf("  %s%s: %d requirements\n", name, version, b.RequirementCount)
	}

	return nil
}

func listTargets(results hdf.HdfResults) error {
	if len(results.Targets) == 0 {
		if jsonOutput {
			fmt.Println("[]")
		} else {
			fmt.Println("No targets defined in this HDF file.")
		}
		return nil
	}

	type targetInfo struct {
		Name string `json:"name"`
		Type string `json:"type"`
		FQDN string `json:"fqdn,omitempty"`
		IP   string `json:"ip_address,omitempty"`
	}

	var targets []targetInfo

	for _, t := range results.Targets {
		info := targetInfo{
			Name: t.Name,
			Type: string(t.Type),
		}
		if t.FQDN != nil {
			info.FQDN = *t.FQDN
		}
		if t.IPAddress != nil {
			info.IP = *t.IPAddress
		}
		targets = append(targets, info)
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(targets, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	fmt.Printf("Targets: %d\n\n", len(targets))
	for _, t := range targets {
		details := ""
		if t.FQDN != "" {
			details = sanitizeOutput(t.FQDN)
		} else if t.IP != "" {
			details = sanitizeOutput(t.IP)
		}
		if details != "" {
			details = fmt.Sprintf(" (%s)", details)
		}
		fmt.Printf("  [%s] %s%s\n", t.Type, sanitizeOutput(t.Name), details)
	}

	return nil
}

const noTitlePlaceholder = "(no title)"

func statusToSymbol(status string) string {
	switch status {
	case StatusPassed:
		return "✓"
	case StatusFailed:
		return "✗"
	case StatusError:
		return "!"
	case StatusNotApplicable:
		return "○"
	case StatusNotReviewed:
		return "?"
	case StatusSkipped:
		return "-"
	default:
		return " "
	}
}
