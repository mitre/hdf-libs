package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
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
  results:          requirements, baselines, components
  baseline:         requirements, groups
  system:           components, interconnections
  plan:             assessments
  amendments:       overrides
  evidence-package: contents

Short aliases for --detail: r (requirements), b (baselines), t (components),
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

	cmd.Flags().StringVar(&detailSection, "detail", "", "Section to expand (requirements, baselines, components, ...)")
	cmd.Flags().StringVarP(&localStatusFilter, "status", "s", "", "Filter by status (passed, failed, error, not_applicable, not_reviewed)")
	cmd.Flags().BoolVarP(&localShowAll, "all", "a", false, "Show all details")

	return cmd
}

// resolveDetailAlias maps short aliases to canonical detail section names.
func resolveDetailAlias(s string) string {
	aliases := map[string]string{
		"r": "requirements", "requirement": "requirements",
		"b": "baselines", "baseline": "baselines",
		"t": "components",
		"c": "components", "component": "components",
		"g": "groups", "group": "groups",
		"a": "assessments", "assessment": "assessments",
		"o": "amendments", "override": "amendments", "overrides": "amendments", "amendment": "amendments",
		"d": "dataFlows", "dataflow": "dataFlows", "dataflows": "dataFlows",
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

	// Detect and validate document type
	docType, typeErr := requireDocumentType(data, []string{"results", "system"}, "hdf list")
	if typeErr != nil {
		return typeErr
	}

	if docType == string(validators.TypeSystem) {
		return runListSystem(data, detail)
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
	case "components":
		return listComponents(results)
	case "amendments":
		return listAppliedAmendments(results)
	default:
		return fmt.Errorf("unknown detail section: %s\nValid sections for results: requirements, baselines, components, amendments", detail)
	}
}

func runListSystem(data []byte, detail string) error {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse system document: %w", err)
	}

	if detail == "" {
		return listSystemSummary(doc)
	}

	section := resolveDetailAlias(strings.ToLower(detail))
	switch section {
	case "components":
		return listSystemComponents(doc)
	case "dataFlows":
		return listSystemDataFlows(doc)
	default:
		return fmt.Errorf("unknown detail section: %s\nValid sections for system: components, dataFlows", detail)
	}
}

func listSystemSummary(doc map[string]interface{}) error {
	name, _ := doc["name"].(string)
	components, _ := doc["components"].([]interface{})
	flows, _ := doc["dataFlows"].([]interface{})

	if jsonOutput {
		summary := map[string]interface{}{
			"name":       name,
			"components": len(components),
			"dataFlows":  len(flows),
		}
		if owner, ok := doc["owner"].(map[string]interface{}); ok {
			summary["owner"] = owner
		}
		output, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	fmt.Printf("System: %s\n", sanitizeOutput(name))
	fmt.Printf("Components:   %d\n", len(components))
	fmt.Printf("Data Flows:   %d\n", len(flows))
	if owner, ok := doc["owner"].(map[string]interface{}); ok {
		if id, ok := owner["identifier"].(string); ok {
			fmt.Printf("Owner:        %s\n", sanitizeOutput(id))
		}
	}
	return nil
}

func listSystemComponents(doc map[string]interface{}) error {
	components, _ := doc["components"].([]interface{})

	if jsonOutput {
		output, _ := json.MarshalIndent(components, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	if len(components) == 0 {
		fmt.Println("No components defined in this system document.")
		return nil
	}

	fmt.Printf("Components: %d\n\n", len(components))
	for _, cRaw := range components {
		comp, ok := cRaw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := comp["name"].(string)
		compType, _ := comp["type"].(string)
		fmt.Printf("  [%s] %s\n", sanitizeOutput(compType), sanitizeOutput(name))
	}
	return nil
}

func listSystemDataFlows(doc map[string]interface{}) error {
	flows, _ := doc["dataFlows"].([]interface{})

	if jsonOutput {
		output, _ := json.MarshalIndent(flows, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	if len(flows) == 0 {
		fmt.Println("No data flows defined in this system document.")
		return nil
	}

	fmt.Printf("Data Flows: %d\n\n", len(flows))
	printDataFlowList(flows)
	return nil
}

func listSummary(results hdf.HDFResults) error {
	if jsonOutput {
		summary := struct {
			Baselines     int `json:"baselines"`
			Requirements  int `json:"requirements"`
			Components    int `json:"components"`
			Passed        int `json:"passed"`
			Failed        int `json:"failed"`
			Error         int `json:"error"`
			NotApplicable int `json:"not_applicable"`
			NotReviewed   int `json:"not_reviewed"`
		}{
			Baselines:  len(results.Baselines),
			Components: len(results.Components),
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
	fmt.Printf("Components:   %d\n", len(results.Components))
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

func listControls(results hdf.HDFResults) error {
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

func buildControlList(results hdf.HDFResults) []controlInfo {
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
	tbl := NewTable(
		Column{Header: "ID"},
		Column{Header: "Status"},
		Column{Header: "Title"},
	)
	for _, c := range controls {
		tbl.AddRow(sanitizeOutput(c.ID), c.Status, truncateTitle(c.Title, 60))
	}
	tbl.Render()
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

func listProfiles(results hdf.HDFResults) error {
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

func listComponents(results hdf.HDFResults) error {
	if len(results.Components) == 0 {
		if jsonOutput {
			fmt.Println("[]")
		} else {
			fmt.Println("No components defined in this HDF file.")
		}
		return nil
	}

	type componentInfo struct {
		Name string `json:"name"`
		Type string `json:"type"`
		FQDN string `json:"fqdn,omitempty"`
		IP   string `json:"ip_address,omitempty"`
	}

	var components []componentInfo

	for _, t := range results.Components {
		info := componentInfo{
			Name: t.Name,
			Type: string(t.Type),
		}
		if t.FQDN != nil {
			info.FQDN = *t.FQDN
		}
		if t.IPAddress != nil {
			info.IP = *t.IPAddress
		}
		components = append(components, info)
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(components, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	if !noHeaders {
		fmt.Printf("Components: %d\n\n", len(components))
	}
	tbl := NewTable(
		Column{Header: "Type"},
		Column{Header: "Name"},
		Column{Header: "FQDN / IP"},
	)
	for _, c := range components {
		addr := ""
		if c.FQDN != "" {
			addr = sanitizeOutput(c.FQDN)
		} else if c.IP != "" {
			addr = sanitizeOutput(c.IP)
		}
		tbl.AddRow(c.Type, sanitizeOutput(c.Name), addr)
	}
	tbl.Render()

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

// listAppliedAmendments shows statusOverrides from within a results file.
func listAppliedAmendments(results hdf.HDFResults) error {
	type appliedAmendment struct {
		RequirementID string `json:"requirementId"`
		Baseline      string `json:"baseline"`
		Type          string `json:"type"`
		Status        string `json:"status"`
		Reason        string `json:"reason"`
		ExpiresAt     string `json:"expiresAt,omitempty"`
	}

	var amendments []appliedAmendment
	for _, baseline := range results.Baselines {
		for _, req := range baseline.Requirements {
			for _, ov := range req.StatusOverrides {
				amendments = append(amendments, appliedAmendment{
					RequirementID: req.ID,
					Baseline:      baseline.Name,
					Type:          string(ov.Type),
					Status:        derefStatusString(ov.Status),
					Reason:        ov.Reason,
					ExpiresAt:     ov.ExpiresAt.Format("2006-01-02"),
				})
			}
		}
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(amendments, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	if len(amendments) == 0 {
		fmt.Println("No amendments applied to this results file.")
		return nil
	}

	if !noHeaders {
		fmt.Printf("Applied Amendments (%d):\n\n", len(amendments))
	}
	tbl := NewTable(
		Column{Header: "Requirement"},
		Column{Header: "Baseline"},
		Column{Header: "Type"},
		Column{Header: "Status"},
		Column{Header: "Expires"},
		Column{Header: "Reason"},
	)
	for _, am := range amendments {
		expires := ""
		if am.ExpiresAt != "" && len(am.ExpiresAt) >= 10 { //nolint:mnd // date prefix length
			expires = am.ExpiresAt[:10]
		}
		tbl.AddRow(am.RequirementID, am.Baseline, am.Type, am.Status, expires, am.Reason)
	}
	tbl.Render()
	return nil
}

func derefStatusString(s *hdf.ResultStatus) string {
	if s == nil {
		return ""
	}
	return string(*s)
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
