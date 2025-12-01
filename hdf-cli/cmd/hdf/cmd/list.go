package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
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
	RunE: runList,
}

var (
	statusFilter string
	showAll      bool
)

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().StringVarP(&statusFilter, "status", "s", "", "Filter by status (passed, failed, error, not_applicable, not_reviewed)")
	listCmd.Flags().BoolVarP(&showAll, "all", "a", false, "Show all details")
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

func listControls(results hdf.HdfResults) error {
	type controlInfo struct {
		ID      string  `json:"id"`
		Title   string  `json:"title,omitempty"`
		Status  string  `json:"status"`
		Impact  float64 `json:"impact"`
		Profile string  `json:"profile"`
	}

	var controls []controlInfo

	for _, profile := range results.Profiles {
		for _, c := range profile.Controls {
			status := determineControlStatus(c)

			// Filter by status if specified
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
				Profile: profile.Name,
			})
		}
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(controls, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	// Human-readable output
	fmt.Printf("Controls: %d\n\n", len(controls))

	// Group by status for readability
	if statusFilter == "" && !showAll {
		// Show summary by status
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
				title := c.Title
				if len(title) > 50 {
					title = title[:47] + "..."
				}
				if title == "" {
					title = noTitlePlaceholder
				}
				fmt.Printf("  %-15s %s\n", c.ID, title)
			}
			fmt.Println()
		}
	} else {
		// Show flat list
		for _, c := range controls {
			statusSymbol := statusToSymbol(c.Status)
			title := c.Title
			if len(title) > 60 {
				title = title[:57] + "..."
			}
			if title == "" {
				title = noTitlePlaceholder
			}
			fmt.Printf("%s %-15s %s\n", statusSymbol, c.ID, title)
		}
	}

	return nil
}

func listProfiles(results hdf.HdfResults) error {
	type profileInfo struct {
		Name         string `json:"name"`
		Title        string `json:"title,omitempty"`
		Version      string `json:"version,omitempty"`
		ControlCount int    `json:"control_count"`
		Status       string `json:"status,omitempty"`
	}

	var profiles []profileInfo

	for _, p := range results.Profiles {
		info := profileInfo{
			Name:         p.Name,
			ControlCount: len(p.Controls),
		}
		if p.Title != nil {
			info.Title = *p.Title
		}
		if p.Version != nil {
			info.Version = *p.Version
		}
		if p.Status != nil {
			info.Status = *p.Status
		}
		profiles = append(profiles, info)
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(profiles, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	fmt.Printf("Profiles: %d\n\n", len(profiles))
	for _, p := range profiles {
		name := p.Name
		if p.Title != "" && p.Title != p.Name {
			name = fmt.Sprintf("%s (%s)", p.Title, p.Name)
		}
		version := ""
		if p.Version != "" {
			version = fmt.Sprintf(" v%s", p.Version)
		}
		fmt.Printf("  %s%s: %d controls\n", name, version, p.ControlCount)
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
			details = t.FQDN
		} else if t.IP != "" {
			details = t.IP
		}
		if details != "" {
			details = fmt.Sprintf(" (%s)", details)
		}
		fmt.Printf("  [%s] %s%s\n", t.Type, t.Name, details)
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
