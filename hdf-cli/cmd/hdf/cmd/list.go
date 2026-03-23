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
func NewListCmd() *cobra.Command {
	var (
		localStatusFilter string
		localShowAll      bool
		detailSection     string
	)

	cmd := &cobra.Command{
		Use:     "list <file> [file...] [--detail <section>]",
		Aliases: []string{"ls"},
		Short:   "Show contents of any HDF document",
		Long: `Show a summary of any HDF document. Auto-detects the document type
(results, baseline, system, plan, amendments, evidence-package).

Multiple files and glob patterns are supported:
  hdf list file1.json file2.json
  hdf list "scans/*.json"

Use --detail to expand a specific section to item-level detail.

Detail sections by document type:
  results:          requirements, baselines, targets
  baseline:         requirements, groups
  system:           components, interconnections
  plan:             assessments
  amendments:       overrides
  evidence-package: contents

Short aliases for --detail: r (requirements), b (baselines), t (targets),
  c (components), g (groups), a (assessments), o (overrides)

Examples:
  hdf list results.json                                Summary of a results file
  hdf list results.json --detail requirements          List individual requirements
  hdf list results.json --detail requirements -s failed
  hdf list file1.json file2.json                       Summary of multiple files
  hdf list system.json                                 Summary of a system document
  hdf list system.json --detail components             List components
  hdf list amendments.json --detail overrides          List amendments`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			statusFilter = localStatusFilter
			showAll = localShowAll
			return runListBulk(cmd, args, detailSection)
		},
	}

	cmd.Flags().StringVar(&detailSection, "detail", "", "Section to expand (requirements, baselines, targets, components, ...)")
	cmd.Flags().StringVarP(&localStatusFilter, "status", "s", "", "Filter by status (passed, failed, error, not_applicable, not_reviewed)")
	cmd.Flags().BoolVarP(&localShowAll, "all", "a", false, "Show all details")

	return cmd
}

// resolveDetailAlias maps short aliases to canonical detail section names.
func resolveDetailAlias(s string) string {
	aliases := map[string]string{
		"r": "requirements", "requirement": "requirements",
		"b": "baselines", "baseline": "baselines",
		"t": "targets", "target": "targets",
		"c": "components", "component": "components",
		"g": "groups", "group": "groups",
		"a": "assessments", "assessment": "assessments",
		"o": "overrides", "override": "overrides",
		"p": "baselines", // legacy alias
	}
	if canonical, ok := aliases[s]; ok {
		return canonical
	}
	return s
}

func runList(_ *cobra.Command, filename, detail string) error {
	data, err := readInputFile(filename)
	if err != nil {
		return err
	}

	results, err := parseHDFResults(data)
	if err != nil {
		return fmt.Errorf("failed to parse HDF file: %w", err)
	}

	if detail == "" {
		return listSummary(results)
	}

	section := resolveDetailAlias(strings.ToLower(detail))
	switch section {
	case "requirements":
		return listControls(results)
	case "baselines":
		return listProfiles(results)
	case "targets":
		return listTargets(results)
	default:
		return fmt.Errorf("unknown detail section: %s\nValid sections for results: requirements, baselines, targets", detail)
	}
}

func listSummary(results hdf.HdfResults) error {
	if jsonOutput {
		summary := struct {
			Baselines     int `json:"baselines"`
			Requirements  int `json:"requirements"`
			Targets       int `json:"targets"`
			Passed        int `json:"passed"`
			Failed        int `json:"failed"`
			Error         int `json:"error"`
			NotApplicable int `json:"not_applicable"`
			NotReviewed   int `json:"not_reviewed"`
		}{
			Baselines: len(results.Baselines),
			Targets:   len(results.Targets),
		}
		for _, b := range results.Baselines {
			summary.Requirements += len(b.Requirements)
			for _, r := range b.Requirements {
				switch determineControlStatus(r) {
				case StatusPassed:
					summary.Passed++
				case StatusFailed:
					summary.Failed++
				case StatusError:
					summary.Error++
				case StatusNotApplicable:
					summary.NotApplicable++
				case StatusNotReviewed:
					summary.NotReviewed++
				}
			}
		}
		output, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	totalReqs := 0
	counts := make(map[string]int)
	for _, b := range results.Baselines {
		totalReqs += len(b.Requirements)
		for _, r := range b.Requirements {
			counts[determineControlStatus(r)]++
		}
	}

	fmt.Printf("Baselines:    %d\n", len(results.Baselines))
	fmt.Printf("Requirements: %d\n", totalReqs)
	fmt.Printf("Targets:      %d\n", len(results.Targets))
	fmt.Println()

	for _, status := range []string{StatusPassed, StatusFailed, StatusError, StatusNotApplicable, StatusNotReviewed} {
		if c := counts[status]; c > 0 {
			fmt.Printf("  %s %-15s %d\n", statusToSymbol(status), status, c)
		}
	}

	return nil
}

type controlInfo struct {
	ID      string  `json:"id"`
	Title   string  `json:"title,omitempty"`
	Status  string  `json:"status"`
	Impact  float64 `json:"impact"`
	Profile string  `json:"baseline"`
}

func listControls(results hdf.HdfResults) error {
	controls := buildControlList(results)

	if jsonOutput {
		return printControlsJSON(controls)
	}

	fmt.Printf("Requirements: %d\n\n", len(controls))

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

// runListBulk dispatches to single-file or multi-file mode.
func runListBulk(cmd *cobra.Command, args []string, detail string) error {
	files, err := expandGlobs(args)
	if err != nil {
		return err
	}

	if len(files) == 1 {
		return runList(cmd, files[0], detail)
	}

	return runBulk(files, "list", "listed", func(file string) error {
		return runList(cmd, file, detail)
	})
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
