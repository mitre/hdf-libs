package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	diff "github.com/mitre/hdf-libs/hdf-diff/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	validators "github.com/mitre/hdf-libs/hdf-validators/go"
	"github.com/spf13/cobra"
)

// ExitCoder is implemented by errors that carry a specific process exit code.
// main.go checks for this interface to use the correct exit code instead of
// defaulting to 1.
type ExitCoder interface {
	error
	ExitCode() int
}

// exitCodeError is returned by runDiff to signal a specific exit code.
type exitCodeError struct {
	code    int
	message string
}

func (e *exitCodeError) Error() string { return e.message }
func (e *exitCodeError) ExitCode() int { return e.code }

// groupByBaseline is the key value for grouping by baseline name.
const groupByBaselineKey = "baseline"

// Output format and SBOM state constants.
const (
	formatJSON   = "json"
	stateAdded   = "added"
	stateRemoved = "removed"
	stateUpdated = "updated"
)

// diffRequirement holds the comparison result for a single requirement.
// JSON field names match the hdf-comparison schema's Requirement_Diff type.
// Before/After are serialized as clean JSON (any) for schema compliance,
// unlike types.RequirementDiff which holds typed pointers.
type diffRequirement struct {
	ID            string                `json:"id"`
	State         diff.RequirementState `json:"state"`
	ChangeReasons []string              `json:"changeReasons"`
	Before        any                   `json:"before"`
	After         any                   `json:"after"`
	FieldChanges  []any                 `json:"fieldChanges"`
	OldStatus     string                `json:"oldEffectiveStatus,omitempty"`
	NewStatus     string                `json:"newEffectiveStatus,omitempty"`
	Title         string                `json:"title,omitempty"`
	Baseline      string                `json:"baseline,omitempty"`

	// groupValue is the resolved value for --group-by (presentation-only, not serialized).
	groupValue string
}

// toCleanJSON converts a Go struct to a map[string]any with nil values stripped.
// Go's encoding/json serializes nil slices/pointers as null, but JSON Schema
// 2020-12 with unevaluatedProperties rejects unexpected nulls. This mirrors
// the JS behavior of omitting undefined fields.
func toCleanJSON(v any) any {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return stripNulls(m)
}

// stripNulls recursively removes null values from JSON-compatible structures.
func stripNulls(v any) any {
	switch val := v.(type) {
	case map[string]any:
		cleaned := make(map[string]any, len(val))
		for k, inner := range val {
			if inner != nil {
				cleaned[k] = stripNulls(inner)
			}
		}
		return cleaned
	case []any:
		cleaned := make([]any, 0, len(val))
		for _, item := range val {
			cleaned = append(cleaned, stripNulls(item))
		}
		return cleaned
	default:
		return v
	}
}

// componentSummary holds per-component compliance information for system-aware diffs.
type componentSummary struct {
	Name            string                 `json:"name"`
	BaselineRefs    []string               `json:"baselineRefs"`
	Summary         diff.ComparisonSummary `json:"summary"`
	OldCompliance   float64                `json:"oldCompliance"`
	NewCompliance   float64                `json:"newCompliance"`
	ComplianceDelta float64                `json:"complianceDelta"`
}

// diffResult is the full output of a diff operation.
// JSON field names match the hdf-comparison schema for validation compliance.
type diffResult struct {
	FormatVersion    string                 `json:"formatVersion"`
	ComparisonMode   string                 `json:"comparisonMode"`
	Sources          []diff.Source          `json:"sources"`
	Summary          diff.ComparisonSummary `json:"summary"`
	RequirementDiffs []diffRequirement      `json:"requirementDiffs"`
	BaselineDiffs    []any                  `json:"baselineDiffs"`
	ComponentDiffs   []componentSummary     `json:"componentDiffs,omitempty"`

	// groupLabel is the column header for the grouping table (presentation-only, not serialized).
	// Set to "Component" for --system, or the group-by key for --group-by.
	groupLabel string
}

// diffFlags holds the local flags for the diff command.
type diffFlags struct {
	format           string
	output           string
	fixed            bool
	regressed        bool
	newOnly          bool
	absent           bool
	all              bool
	exitCode         bool
	detailedExitCode bool
	quiet            bool
	stat             bool
	nameOnly         bool
	system           string
	groupBy          string
	sbomMode         bool
}

// NewDiffCmd creates a new diff command with fresh state.
func NewDiffCmd() *cobra.Command {
	var flags diffFlags

	cmd := &cobra.Command{
		Use:   "diff <old-file> <new-file>",
		Short: "Compare two HDF documents (results or system)",
		Long: `Compare two HDF documents and show what changed between them.

Supports results documents (temporal mode) and system documents (systemDrift mode).
Document type is auto-detected; system documents are compared by component matching.

Requirements are matched by ID across the two documents and classified as:
  fixed      - was failing, now passing
  regressed  - was passing, now failing
  unchanged  - same status in both
  updated    - status changed but neither fixed nor regressed
  new        - present only in the new file
  absent     - present only in the old file

Exit codes (--exit-code): GNU diff compatible
  0 - no differences found (assessments are identical)
  1 - differences found (any kind)
  2 - error (file not found, parse failure, etc.)

Exit codes (--detailed-exitcode): nuanced security outcomes
  0  - identical (no differences)
  1  - error (file not found, parse failure)
  10 - fixes only (security posture improved)
  11 - regressions only (security posture degraded)
  12 - mixed fixes and regressions
  13 - baseline changed (only new/absent controls)
  14 - metadata drift only (tags, descriptions changed)

Examples:
  hdf diff scan-before.json scan-after.json
  hdf diff scan-before.json scan-after.json --json
  hdf diff scan-before.json scan-after.json --fixed
  hdf diff scan-before.json scan-after.json -f markdown
  hdf diff scan-before.json scan-after.json --exit-code
  hdf diff scan-before.json scan-after.json --detailed-exitcode
  hdf diff scan-before.json scan-after.json -q           # quiet: exit code only
  hdf diff scan-before.json scan-after.json --stat        # summary counts only
  hdf diff scan-before.json scan-after.json --name-only   # changed requirement IDs only
  hdf diff old.json new.json --system system.json         # component-aware comparison
  hdf diff old.json new.json --group-by baseline          # group by baseline name
  hdf diff --sbom old.cdx.json new.cdx.json               # SBOM comparison mode
  hdf diff old-system.json new-system.json                # System document comparison`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd, args, &flags)
		},
	}

	cmd.Flags().StringVarP(&flags.format, "format", "f", "table", "Output format: json, table, markdown")
	cmd.Flags().StringVarP(&flags.output, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().BoolVar(&flags.fixed, "fixed", false, "Show only fixed requirements")
	cmd.Flags().BoolVar(&flags.regressed, "regressed", false, "Show only regressions")
	cmd.Flags().BoolVar(&flags.newOnly, "new", false, "Show only new requirements")
	cmd.Flags().BoolVar(&flags.absent, "absent", false, "Show only absent requirements")
	cmd.Flags().BoolVar(&flags.all, "all", false, "Include unchanged requirements/components in output")
	cmd.Flags().BoolVar(&flags.exitCode, "exit-code", false, "Use POSIX diff exit codes: 0=identical, 1=differences, 2=error")
	cmd.Flags().BoolVar(&flags.detailedExitCode, "detailed-exitcode", false,
		"Use detailed exit codes: 0=identical, 10=fixes, 11=regressions, 12=mixed, 13=baseline, 14=drift")
	cmd.Flags().BoolVarP(&flags.quiet, "quiet", "q", false, "Suppress output, return exit code only (implies --exit-code)")
	cmd.Flags().BoolVar(&flags.stat, "stat", false, "Show summary counts only (like git diff --stat)")
	cmd.Flags().BoolVar(&flags.nameOnly, "name-only", false, "List only changed requirement IDs")
	cmd.Flags().StringVar(&flags.system, "system", "", "System document for component-aware comparison")
	cmd.Flags().StringVar(&flags.groupBy, "group-by", "", "Group results by label key (e.g., baseline)")
	cmd.Flags().BoolVar(&flags.sbomMode, "sbom", false, "SBOM comparison mode: treat inputs as CycloneDX or SPDX documents")

	return cmd
}

func runDiff(_ *cobra.Command, args []string, flags *diffFlags) error {
	if flags.system != "" && flags.groupBy != "" {
		return fmt.Errorf("--system and --group-by are mutually exclusive")
	}

	// SBOM comparison mode
	if flags.sbomMode {
		return runSbomDiff(args, flags)
	}

	oldFile := args[0]
	newFile := args[1]

	// Read both files raw and detect document types before parsing
	oldData, err := readInputFile(oldFile)
	if err != nil {
		return err
	}
	newData, err := readInputFile(newFile)
	if err != nil {
		return err
	}

	oldType := detectHDFDocumentType(oldData)
	newType := detectHDFDocumentType(newData)

	// System drift mode: both inputs are system documents
	if oldType == string(validators.TypeSystem) && newType == string(validators.TypeSystem) {
		return runSystemDiff(oldData, newData, flags, oldFile, newFile)
	}

	// Reject mismatched document types with a clear error
	if oldType != newType {
		return fmt.Errorf("cannot diff %s document (%s) against %s document (%s) — both files must be the same type",
			oldType, oldFile, newType, newFile)
	}

	// Only results documents are supported for requirement-level diff
	if oldType != string(validators.TypeResults) {
		return fmt.Errorf("hdf diff does not support %s documents — only results and system documents can be compared", oldType)
	}

	oldResults, newResults, err := loadDiffInputsFromData(oldData, newData, oldFile, newFile)
	if err != nil {
		return err
	}

	comp, err := diff.DiffHdf(oldResults, []hdf.HDFResults{newResults}, diff.Options{})
	if err != nil {
		return fmt.Errorf("comparison failed: %w", err)
	}
	result := engineResultToDiffResult(comp, oldFile, newFile)

	if err := applyComponentGrouping(flags, oldResults, newResults, &result); err != nil {
		printError(err.Error())
		return err
	}

	filtered := applyDiffFilters(result, flags)

	if flags.quiet {
		flags.exitCode = true
	}
	if !flags.quiet {
		if err := renderDiffOutput(filtered, flags, oldFile, newFile); err != nil {
			return err
		}
	}

	return computeDiffExitCode(result.Summary, flags)
}

// loadDiffInputs reads and parses the old and new HDF results files.
//
//nolint:unparam // used in coverage tests; first return value used by callers
func loadDiffInputs(oldFile, newFile string) (hdf.HDFResults, hdf.HDFResults, error) {
	oldData, err := readInputFile(oldFile)
	if err != nil {
		printError(err.Error())
		return hdf.HDFResults{}, hdf.HDFResults{}, err
	}
	newData, err := readInputFile(newFile)
	if err != nil {
		printError(err.Error())
		return hdf.HDFResults{}, hdf.HDFResults{}, err
	}
	return loadDiffInputsFromData(oldData, newData, oldFile, newFile)
}

// loadDiffInputsFromData parses pre-read data into HDF results.
func loadDiffInputsFromData(oldData, newData []byte, oldFile, newFile string) (hdf.HDFResults, hdf.HDFResults, error) {
	oldResults, err := parseHDFResults(oldData)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse old HDF file (%s): %v", oldFile, err))
		return hdf.HDFResults{}, hdf.HDFResults{}, err
	}
	newResults, err := parseHDFResults(newData)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse new HDF file (%s): %v", newFile, err))
		return hdf.HDFResults{}, hdf.HDFResults{}, err
	}
	return oldResults, newResults, nil
}

// engineResultToDiffResult converts the engine's typed HdfComparison to the CLI's
// diffResult for rendering. This is the bridge between hdf-diff/go and the CLI layer.
func engineResultToDiffResult(comp diff.HdfComparison, oldFile, newFile string) diffResult {
	// Convert requirement diffs
	reqs := make([]diffRequirement, 0, len(comp.RequirementDiffs))
	for _, rd := range comp.RequirementDiffs {
		dr := diffRequirement{
			ID:        rd.ID,
			State:     rd.State,
			Title:     rd.Title,
			Baseline:  rd.Baseline,
			OldStatus: rd.OldEffectiveStatus,
			NewStatus: rd.NewEffectiveStatus,
		}

		// Convert change reasons (typed enum → string)
		reasons := make([]string, 0, len(rd.ChangeReasons))
		for _, cr := range rd.ChangeReasons {
			reasons = append(reasons, string(cr))
		}
		dr.ChangeReasons = reasons

		// Convert field changes (typed struct → any)
		fieldChanges := make([]any, 0, len(rd.FieldChanges))
		for _, fc := range rd.FieldChanges {
			fieldChanges = append(fieldChanges, fc)
		}
		dr.FieldChanges = fieldChanges

		// Convert before/after: serialize to clean JSON (strips Go nil→null)
		if rd.Before != nil {
			dr.Before = toCleanJSON(rd.Before)
		}
		if rd.After != nil {
			dr.After = toCleanJSON(rd.After)
		}

		reqs = append(reqs, dr)
	}

	// Convert summary
	summary := diff.ComparisonSummary{
		Total:             comp.Summary.Total,
		Fixed:             comp.Summary.Fixed,
		Regressed:         comp.Summary.Regressed,
		New:               comp.Summary.New,
		Absent:            comp.Summary.Absent,
		Unchanged:         comp.Summary.Unchanged,
		Updated:           comp.Summary.Updated,
		MatchedCount:      comp.Summary.MatchedCount,
		UnmatchedOldCount: comp.Summary.UnmatchedOldCount,
		UnmatchedNewCount: comp.Summary.UnmatchedNewCount,
	}

	// Convert sources — use file paths as labels (matches old behavior)
	sources := []diff.Source{
		{Role: "old", Label: filepath.Base(oldFile)},
		{Role: "new", Label: filepath.Base(newFile)},
	}

	// Convert baseline diffs
	baselineDiffs := make([]any, 0, len(comp.BaselineDiffs))
	for _, bd := range comp.BaselineDiffs {
		baselineDiffs = append(baselineDiffs, bd)
	}
	if len(baselineDiffs) == 0 {
		baselineDiffs = []any{}
	}

	return diffResult{
		FormatVersion:    comp.FormatVersion,
		ComparisonMode:   string(comp.ComparisonMode),
		Sources:          sources,
		Summary:          summary,
		RequirementDiffs: reqs,
		BaselineDiffs:    baselineDiffs,
	}
}

// renderDiffOutput writes the diff output in the requested format.
func renderDiffOutput(filtered diffResult, flags *diffFlags, oldFile, newFile string) error {
	// For table and markdown output, hide unchanged unless --all is set.
	// JSON and --stat always include everything.
	display := filtered
	if !flags.all && !flags.nameOnly {
		display = stripUnchanged(filtered)
	}

	switch {
	case flags.nameOnly:
		outputDiffNameOnly(filtered) // nameOnly already skips unchanged
	case flags.stat:
		outputDiffSummary(filtered.Summary) // stat uses full summary
	case jsonOutput || flags.format == formatJSON:
		if err := outputDiffJSON(filtered); err != nil { // JSON includes all
			return err
		}
	case flags.format == "markdown":
		outputDiffMarkdown(display, oldFile, newFile)
		if flags.groupBy == "" {
			outputComponentSummariesIfPresent(filtered)
		}
	default:
		outputDiffTable(display, oldFile, newFile)
		if flags.groupBy == "" {
			outputComponentSummariesIfPresent(filtered)
		}
	}
	return nil
}

// stripUnchanged returns a copy of the result with unchanged requirements removed.
// The summary is preserved from the original (full counts).
func stripUnchanged(result diffResult) diffResult {
	var changed []diffRequirement
	for _, req := range result.RequirementDiffs {
		if req.State != diff.StateUnchanged {
			changed = append(changed, req)
		}
	}
	return diffResult{
		FormatVersion:    result.FormatVersion,
		ComparisonMode:   result.ComparisonMode,
		Sources:          result.Sources,
		Summary:          result.Summary, // keep full summary
		RequirementDiffs: changed,
		BaselineDiffs:    result.BaselineDiffs,
		ComponentDiffs:   result.ComponentDiffs,
		groupLabel:       result.groupLabel,
	}
}

// outputComponentSummariesIfPresent prints component/group summaries when they exist.
func outputComponentSummariesIfPresent(result diffResult) {
	if len(result.ComponentDiffs) > 0 {
		fmt.Println()
		label := result.groupLabel
		if label == "" {
			label = "Component"
		}
		outputComponentSummaries(result.ComponentDiffs, label)
	}
}

// computeDiffExitCode returns an exit code error if --exit-code or --detailed-exitcode is set.
func computeDiffExitCode(summary diff.ComparisonSummary, flags *diffFlags) error {
	if flags.detailedExitCode {
		code := diff.ComputeDetailedExitCode(summary)
		if code != 0 {
			return &exitCodeError{code: code, message: fmt.Sprintf("detailed exit code: %d", code)}
		}
		return nil
	}
	// Basic exit codes are always active (GNU diff convention):
	// 0 = identical, 1 = differences found
	code := diff.ComputeBasicExitCode(summary)
	if code != 0 {
		return &exitCodeError{code: code, message: "differences found"}
	}
	return nil
}

// isFailingStatus returns true if the status is considered failing.
func isFailingStatus(status string) bool {
	return status == StatusFailed || status == StatusError || status == StatusNotReviewed
}

// buildDiffSummary computes summary counts from a slice of requirements.
func buildDiffSummary(requirements []diffRequirement) diff.ComparisonSummary {
	summary := diff.ComparisonSummary{Total: len(requirements)}
	for _, req := range requirements {
		switch req.State { //nolint:exhaustive // moved/split/merged reserved for v1.1
		case diff.StateFixed:
			summary.Fixed++
		case diff.StateRegressed:
			summary.Regressed++
		case diff.StateNew:
			summary.New++
		case diff.StateAbsent:
			summary.Absent++
		case diff.StateUnchanged:
			summary.Unchanged++
		case diff.StateUpdated:
			summary.Updated++
		}
	}
	return summary
}

// applyDiffFilters filters the diff result based on the provided flags.
func applyDiffFilters(result diffResult, flags *diffFlags) diffResult {
	if !flags.fixed && !flags.regressed && !flags.newOnly && !flags.absent {
		return result
	}

	allowed := map[diff.RequirementState]bool{
		diff.StateFixed:     flags.fixed,
		diff.StateRegressed: flags.regressed,
		diff.StateNew:       flags.newOnly,
		diff.StateAbsent:    flags.absent,
	}

	var filtered []diffRequirement
	for _, req := range result.RequirementDiffs {
		if allowed[req.State] {
			filtered = append(filtered, req)
		}
	}

	return diffResult{
		FormatVersion:    result.FormatVersion,
		ComparisonMode:   result.ComparisonMode,
		Sources:          result.Sources,
		Summary:          buildDiffSummary(filtered),
		RequirementDiffs: filtered,
		BaselineDiffs:    result.BaselineDiffs,
		ComponentDiffs:   result.ComponentDiffs,
		groupLabel:       result.groupLabel,
	}
}

// --- Output formatters ---

func outputDiffJSON(result diffResult) error {
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func outputDiffTable(result diffResult, oldFile, newFile string) {
	if !noHeaders {
		fmt.Printf("HDF Comparison: %s → %s\n", sanitizeOutput(oldFile), sanitizeOutput(newFile))
		fmt.Println()
	}

	columns := []Column{
		{Header: "ID"},
		{Header: "Title"},
		{Header: "Old Status"},
		{Header: "New Status"},
		{Header: "State"},
	}
	hasGroupBy := result.groupLabel != ""
	if hasGroupBy {
		columns = append(columns, Column{Header: result.groupLabel})
	}

	tbl := NewTable(columns...)
	for _, req := range result.RequirementDiffs {
		oldStatus := req.OldStatus
		newStatus := req.NewStatus
		if oldStatus == "" {
			oldStatus = "-"
		}
		if newStatus == "" {
			newStatus = "-"
		}
		row := []string{
			sanitizeOutput(req.ID),
			sanitizeOutput(truncate(req.Title, 40)),
			oldStatus,
			newStatus,
			string(req.State),
		}
		if hasGroupBy {
			row = append(row, sanitizeOutput(req.groupValue))
		}
		tbl.AddRow(row...)
	}
	tbl.Render()

	if !noHeaders {
		fmt.Println()
		outputDiffSummary(result.Summary)
	}
}

func outputDiffMarkdown(result diffResult, oldFile, newFile string) {
	fmt.Printf("## HDF Comparison: %s → %s\n", sanitizeOutput(oldFile), sanitizeOutput(newFile))
	fmt.Println()

	hasGroupBy := result.groupLabel != ""
	if hasGroupBy {
		fmt.Printf("| ID | Title | Old Status | New Status | State | %s |\n", result.groupLabel)
		fmt.Printf("|----|-------|------------|------------|-------|%s|\n", strings.Repeat("-", len(result.groupLabel)+2))
	} else {
		fmt.Println("| ID | Title | Old Status | New Status | State |")
		fmt.Println("|----|-------|------------|------------|-------|")
	}

	for _, req := range result.RequirementDiffs {
		title := sanitizeOutput(truncate(req.Title, 40))
		oldStatus := req.OldStatus
		newStatus := req.NewStatus
		if oldStatus == "" {
			oldStatus = "-"
		}
		if newStatus == "" {
			newStatus = "-"
		}
		if hasGroupBy {
			fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
				sanitizeOutput(req.ID), title, oldStatus, newStatus, req.State, sanitizeOutput(req.groupValue))
		} else {
			fmt.Printf("| %s | %s | %s | %s | %s |\n",
				sanitizeOutput(req.ID), title, oldStatus, newStatus, req.State)
		}
	}

	fmt.Println()
	outputDiffSummary(result.Summary)
}

// titleCase uppercases the first letter of a string.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func outputDiffSummary(summary diff.ComparisonSummary) {
	parts := []string{
		fmt.Sprintf("%d fixed", summary.Fixed),
		fmt.Sprintf("%d regressed", summary.Regressed),
		fmt.Sprintf("%d new", summary.New),
		fmt.Sprintf("%d absent", summary.Absent),
		fmt.Sprintf("%d unchanged", summary.Unchanged),
		fmt.Sprintf("%d updated", summary.Updated),
	}
	fmt.Printf("Summary: %s (%d total)\n", strings.Join(parts, ", "), summary.Total)
}

func outputDiffNameOnly(result diffResult) {
	for _, req := range result.RequirementDiffs {
		if req.State != diff.StateUnchanged {
			fmt.Println(sanitizeOutput(req.ID))
		}
	}
}

// truncate truncates a string to the given length, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// --- System-aware grouping ---

// systemDocument represents the minimal structure of a system document needed for grouping.
type systemDocument struct {
	Name       string            `json:"name"`
	Components []systemComponent `json:"components"`
}

// systemComponent represents a component in a system document.
type systemComponent struct {
	Name         string   `json:"name"`
	BaselineRefs []string `json:"baselineRefs"`
}

// parseSystemDocument reads and parses a system document from a file path.
func parseSystemDocument(path string) (systemDocument, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is user-provided CLI arg
	if err != nil {
		return systemDocument{}, fmt.Errorf("failed to read system document: %w", err)
	}
	var doc systemDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return systemDocument{}, fmt.Errorf("failed to parse system document: %w", err)
	}
	return doc, nil
}

// applyComponentGrouping applies either system-aware or group-by column to the diff result.
// --system produces a separate component summary table with compliance percentages.
// --group-by adds a column to the main diff table showing the group value per requirement.
func applyComponentGrouping(flags *diffFlags, oldResults, newResults hdf.HDFResults, result *diffResult) error {
	if flags.system != "" {
		summaries, err := applySystemGrouping(flags.system, oldResults, newResults, *result)
		if err != nil {
			return err
		}
		result.ComponentDiffs = summaries
		result.groupLabel = "Component"
	}
	if flags.groupBy != "" {
		resolveGroupValues(flags.groupBy, oldResults, newResults, result)
		result.groupLabel = titleCase(strings.TrimPrefix(flags.groupBy, "labels."))
	}
	return nil
}

// resolveGroupValues populates the groupValue field on each requirement based on the group key.
// Recognized requirement-level fields: "baseline", "id", "status".
// Other keys look up baseline extensions.labels.
func resolveGroupValues(groupKey string, oldResults, newResults hdf.HDFResults, result *diffResult) {
	groupKey = strings.TrimPrefix(groupKey, "labels.")

	switch groupKey {
	case groupByBaselineKey:
		for i := range result.RequirementDiffs {
			result.RequirementDiffs[i].groupValue = result.RequirementDiffs[i].Baseline
		}
	case "id":
		for i := range result.RequirementDiffs {
			result.RequirementDiffs[i].groupValue = result.RequirementDiffs[i].ID
		}
	case "status":
		for i := range result.RequirementDiffs {
			req := &result.RequirementDiffs[i]
			if req.NewStatus != "" {
				req.groupValue = req.NewStatus
			} else {
				req.groupValue = req.OldStatus
			}
		}
	default:
		// Label key: look up in baseline extensions.labels
		baselineGroupMap := make(map[string]string)
		for _, results := range []hdf.HDFResults{oldResults, newResults} {
			for _, baseline := range results.Baselines {
				if baseline.Extensions != nil {
					if labels, ok := baseline.Extensions["labels"].(map[string]interface{}); ok {
						if val, ok := labels[groupKey].(string); ok {
							baselineGroupMap[baseline.Name] = val
						}
					}
				}
			}
		}
		for i := range result.RequirementDiffs {
			req := &result.RequirementDiffs[i]
			if val, ok := baselineGroupMap[req.Baseline]; ok {
				req.groupValue = val
			}
		}
	}
}

// applySystemGrouping reads the system document and groups diff requirements by component.
// Components reference baselines via baselineRefs; requirements are matched to components
// by their baseline membership.
func applySystemGrouping(
	systemPath string,
	oldResults, newResults hdf.HDFResults,
	result diffResult,
) ([]componentSummary, error) {
	sysDoc, err := parseSystemDocument(systemPath)
	if err != nil {
		return nil, err
	}

	return buildComponentSummaries(sysDoc.Components, oldResults, newResults, result), nil
}

// buildComponentSummaries creates per-component summaries by grouping requirements
// that belong to each component's referenced baselines.
func buildComponentSummaries(
	components []systemComponent,
	oldResults, newResults hdf.HDFResults,
	result diffResult,
) []componentSummary {
	var summaries []componentSummary

	for _, comp := range components {
		// Build a set of baseline names this component references
		baselineSet := make(map[string]bool, len(comp.BaselineRefs))
		for _, ref := range comp.BaselineRefs {
			baselineSet[ref] = true
		}

		// Filter requirements belonging to this component's baselines
		var compReqs []diffRequirement
		for _, req := range result.RequirementDiffs {
			if baselineSet[req.Baseline] {
				compReqs = append(compReqs, req)
			}
		}

		compSummary := buildDiffSummary(compReqs)

		// Compute compliance percentages from the original results
		oldCompliance := computeBaselineCompliance(oldResults, baselineSet)
		newCompliance := computeBaselineCompliance(newResults, baselineSet)

		summaries = append(summaries, componentSummary{
			Name:            comp.Name,
			BaselineRefs:    comp.BaselineRefs,
			Summary:         compSummary,
			OldCompliance:   oldCompliance,
			NewCompliance:   newCompliance,
			ComplianceDelta: newCompliance - oldCompliance,
		})
	}

	return summaries
}

// computeBaselineCompliance computes the compliance percentage for a set of baselines
// in an HDF results document. Compliance = passed / (passed + failed + error + notReviewed).
func computeBaselineCompliance(results hdf.HDFResults, baselineSet map[string]bool) float64 {
	var passed, total int
	for _, baseline := range results.Baselines {
		if !baselineSet[baseline.Name] {
			continue
		}
		for _, req := range baseline.Requirements {
			status := determineControlStatus(req)
			if status == StatusPassed || isFailingStatus(status) {
				total++
				if status == StatusPassed {
					passed++
				}
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(passed) / float64(total) * 100 //nolint:mnd // percentage conversion
}

// runSbomDiff handles the --sbom flag: reads two SBOM files and outputs a package diff.
func runSbomDiff(args []string, flags *diffFlags) error {
	oldData, err := os.ReadFile(args[0]) //nolint:gosec // path is user-provided CLI arg
	if err != nil {
		return fmt.Errorf("failed to read old SBOM file: %w", err)
	}
	newData, err := os.ReadFile(args[1]) //nolint:gosec // path is user-provided CLI arg
	if err != nil {
		return fmt.Errorf("failed to read new SBOM file: %w", err)
	}

	result, err := diff.DiffSBOMs(oldData, newData)
	if err != nil {
		return err
	}

	if flags.quiet {
		return nil
	}

	if jsonOutput || flags.format == formatJSON {
		return outputSbomJSON(result)
	}

	outputSbomTable(result, args[0], args[1])
	return nil
}

// outputSbomJSON renders the SBOM diff result as JSON.
func outputSbomJSON(result *diff.DiffResult) error {
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

// outputSbomTable renders the SBOM diff result as a human-readable table.
func outputSbomTable(result *diff.DiffResult, oldFile, newFile string) {
	if !noHeaders {
		fmt.Printf("SBOM Comparison: %s → %s\n\n", sanitizeOutput(oldFile), sanitizeOutput(newFile))
	}

	tbl := NewTable(
		Column{Header: "Package"},
		Column{Header: "Old Version"},
		Column{Header: "New Version"},
		Column{Header: "State"},
	)
	for _, d := range result.PackageDiffs {
		tbl.AddRow(sanitizeOutput(d.Name), d.OldVersion, d.NewVersion, d.State)
	}
	tbl.Render()

	if !noHeaders {
		fmt.Printf("\nSummary: %d added, %d removed, %d updated, %d unchanged\n",
			result.Added, result.Removed, result.Updated, result.Unchanged)
	}
}

// --- System document diff (systemDrift mode) ---

// systemDiffComponent holds the comparison result for a single component.
type systemDiffComponent struct {
	Name         string                  `json:"name"`
	State        diff.RequirementState   `json:"state"`
	FieldChanges []systemDiffFieldChange `json:"fieldChanges,omitempty"`
}

// systemDiffFieldChange represents a single field change on a component or system.
type systemDiffFieldChange struct {
	Op       string      `json:"op"`   // "add", "remove", "replace"
	Path     string      `json:"path"` // field name
	OldValue interface{} `json:"oldValue,omitempty"`
	NewValue interface{} `json:"newValue,omitempty"`
}

// systemDiffDataFlow represents a data flow change.
type systemDiffDataFlow struct {
	State string                 `json:"state"` // "added", "removed", "updated"
	Flow  map[string]interface{} `json:"flow"`
}

// systemDiffResult is the full output of a system diff operation.
type systemDiffResult struct {
	FormatVersion  string                 `json:"formatVersion"`
	ComparisonMode string                 `json:"comparisonMode"`
	Summary        diff.ComparisonSummary `json:"summary"`
	ComponentDiffs []systemDiffComponent  `json:"componentDiffs"`
	Extensions     map[string]interface{} `json:"extensions,omitempty"`
}

// runSystemDiff compares two system documents in systemDrift mode.
func runSystemDiff(oldData, newData []byte, flags *diffFlags, oldFile, newFile string) error {
	// Parse into generic maps (no schema validation — system docs don't need
	// the HDF results pipeline, but we validate they're valid JSON)
	var oldSys, newSys map[string]interface{}
	if err := json.Unmarshal(oldData, &oldSys); err != nil {
		return fmt.Errorf("failed to parse old system document: %w", err)
	}
	if err := json.Unmarshal(newData, &newSys); err != nil {
		return fmt.Errorf("failed to parse new system document: %w", err)
	}

	comp, err := diff.DiffSystems(oldSys, newSys)
	if err != nil {
		return fmt.Errorf("system comparison failed: %w", err)
	}
	result := engineSystemResultToSystemDiffResult(comp)

	if flags.quiet {
		flags.exitCode = true
	}
	if !flags.quiet {
		if err := renderSystemDiffOutput(result, flags, oldFile, newFile); err != nil {
			return err
		}
	}

	return computeSystemDiffExitCode(result.Summary, flags)
}

// engineSystemResultToSystemDiffResult converts the engine's HdfComparison to the CLI's
// systemDiffResult for rendering.
func engineSystemResultToSystemDiffResult(comp diff.HdfComparison) systemDiffResult {
	// Convert component diffs
	componentDiffs := make([]systemDiffComponent, 0, len(comp.ComponentDiffs))
	for _, cd := range comp.ComponentDiffs {
		sdc := systemDiffComponent{
			Name:  cd.Name,
			State: cd.State,
		}
		// Convert field changes
		if len(cd.FieldChanges) > 0 {
			changes := make([]systemDiffFieldChange, 0, len(cd.FieldChanges))
			for _, fc := range cd.FieldChanges {
				changes = append(changes, systemDiffFieldChange{
					Op:       string(fc.Op),
					Path:     fc.Path,
					OldValue: fc.OldValue,
					NewValue: fc.NewValue,
				})
			}
			sdc.FieldChanges = changes
		}
		componentDiffs = append(componentDiffs, sdc)
	}

	// Convert summary
	summary := diff.ComparisonSummary{
		Total:             comp.Summary.Total,
		New:               comp.Summary.New,
		Absent:            comp.Summary.Absent,
		Unchanged:         comp.Summary.Unchanged,
		Updated:           comp.Summary.Updated,
		MatchedCount:      comp.Summary.MatchedCount,
		UnmatchedOldCount: comp.Summary.UnmatchedOldCount,
		UnmatchedNewCount: comp.Summary.UnmatchedNewCount,
	}

	// Convert extensions — preserve systemFieldChanges and dataFlowChanges
	var extensions map[string]interface{}
	if comp.Extensions != nil {
		extensions = make(map[string]interface{})

		// Convert systemFieldChanges ([]types.FieldChange → []systemDiffFieldChange)
		if sfc, ok := comp.Extensions["systemFieldChanges"]; ok {
			if typedChanges, ok := sfc.([]diff.FieldChange); ok {
				converted := make([]systemDiffFieldChange, 0, len(typedChanges))
				for _, fc := range typedChanges {
					converted = append(converted, systemDiffFieldChange{
						Op:       string(fc.Op),
						Path:     fc.Path,
						OldValue: fc.OldValue,
						NewValue: fc.NewValue,
					})
				}
				extensions["systemFieldChanges"] = converted
			} else {
				extensions["systemFieldChanges"] = sfc
			}
		}

		// Convert dataFlowChanges ([]diff.DataFlowChange → []systemDiffDataFlow)
		if dfc, ok := comp.Extensions["dataFlowChanges"]; ok {
			if typedChanges, ok := dfc.([]diff.DataFlowChange); ok {
				converted := make([]systemDiffDataFlow, 0, len(typedChanges))
				for _, df := range typedChanges {
					converted = append(converted, systemDiffDataFlow{
						State: df.State,
						Flow:  df.Flow,
					})
				}
				extensions["dataFlowChanges"] = converted
			} else {
				extensions["dataFlowChanges"] = dfc
			}
		}

		if len(extensions) == 0 {
			extensions = nil
		}
	}

	return systemDiffResult{
		FormatVersion:  comp.FormatVersion,
		ComparisonMode: string(comp.ComparisonMode),
		Summary:        summary,
		ComponentDiffs: componentDiffs,
		Extensions:     extensions,
	}
}

// computeSystemDiffExitCode returns an exit code for system diffs.
func computeSystemDiffExitCode(summary diff.ComparisonSummary, flags *diffFlags) error {
	return computeDiffExitCode(summary, flags)
}

// renderSystemDiffOutput renders system diff output in the requested format.
func renderSystemDiffOutput(result systemDiffResult, flags *diffFlags, oldFile, newFile string) error {
	// For table and markdown output, hide unchanged unless --all is set.
	display := result
	if !flags.all && !flags.nameOnly {
		display = stripUnchangedComponents(result)
	}

	switch {
	case flags.nameOnly:
		outputSystemDiffNameOnly(result) // nameOnly already skips unchanged
	case flags.stat:
		outputSystemDiffSummary(result.Summary, result.Extensions)
	case jsonOutput || flags.format == formatJSON:
		return outputSystemDiffJSON(result) // JSON includes all
	case flags.format == "markdown":
		outputSystemDiffMarkdown(display, oldFile, newFile)
	default:
		outputSystemDiffTable(display, oldFile, newFile)
	}
	return nil
}

// stripUnchangedComponents returns a copy with unchanged components removed.
// The summary is preserved from the original (full counts).
func stripUnchangedComponents(result systemDiffResult) systemDiffResult {
	var changed []systemDiffComponent
	for _, cd := range result.ComponentDiffs {
		if cd.State != diff.StateUnchanged {
			changed = append(changed, cd)
		}
	}
	return systemDiffResult{
		FormatVersion:  result.FormatVersion,
		ComparisonMode: result.ComparisonMode,
		Summary:        result.Summary,
		ComponentDiffs: changed,
		Extensions:     result.Extensions,
	}
}

func outputSystemDiffJSON(result systemDiffResult) error {
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func outputSystemDiffTable(result systemDiffResult, oldFile, newFile string) {
	if !noHeaders {
		fmt.Printf("System Comparison: %s → %s\n", sanitizeOutput(oldFile), sanitizeOutput(newFile))
		fmt.Println()
		fmt.Println("Components:")
	}
	tbl := NewTable(
		Column{Header: "Component"},
		Column{Header: "State"},
		Column{Header: "Changes"},
	)
	for _, cd := range result.ComponentDiffs {
		changesStr := ""
		if len(cd.FieldChanges) > 0 {
			fields := make([]string, 0, len(cd.FieldChanges))
			for _, fc := range cd.FieldChanges {
				fields = append(fields, fc.Op+" "+fc.Path)
			}
			changesStr = strings.Join(fields, ", ")
		}
		tbl.AddRow(sanitizeOutput(cd.Name), string(cd.State), changesStr)
	}
	tbl.Render()

	// Show data flow changes as a detail section
	outputDataFlowDetails(result.Extensions)

	if !noHeaders {
		fmt.Println()
		outputSystemDiffSummary(result.Summary, result.Extensions)
	}
}

// outputDataFlowDetails prints individual data flow changes when present.
func outputDataFlowDetails(extensions map[string]interface{}) {
	if extensions == nil {
		return
	}
	dfChanges, ok := extensions["dataFlowChanges"].([]systemDiffDataFlow)
	if !ok || len(dfChanges) == 0 {
		return
	}

	if !noHeaders {
		fmt.Println()
		fmt.Println("Data Flows:")
	}
	tbl := NewTable(
		Column{Header: "From"},
		Column{Header: "To"},
		Column{Header: "Protocol"},
		Column{Header: "State"},
	)
	for _, df := range dfChanges {
		from, _ := df.Flow["from"].(string)
		to, _ := df.Flow["to"].(string)
		protocol, _ := df.Flow["protocol"].(string)
		tbl.AddRow(sanitizeOutput(from), sanitizeOutput(to), protocol, df.State)
	}
	tbl.Render()
}

func outputSystemDiffMarkdown(result systemDiffResult, oldFile, newFile string) {
	fmt.Printf("## System Comparison: %s → %s\n\n", sanitizeOutput(oldFile), sanitizeOutput(newFile))

	fmt.Println("| Component | State | Changes |")
	fmt.Println("|-----------|-------|---------|")

	for _, cd := range result.ComponentDiffs {
		changesStr := "-"
		if len(cd.FieldChanges) > 0 {
			fields := make([]string, 0, len(cd.FieldChanges))
			for _, fc := range cd.FieldChanges {
				fields = append(fields, fc.Path)
			}
			changesStr = strings.Join(fields, ", ")
		}
		fmt.Printf("| %s | %s | %s |\n",
			sanitizeOutput(cd.Name), cd.State, sanitizeOutput(changesStr))
	}

	fmt.Println()
	outputSystemDiffSummary(result.Summary, result.Extensions)
}

func outputSystemDiffSummary(summary diff.ComparisonSummary, extensions map[string]interface{}) {
	parts := []string{
		fmt.Sprintf("%d new", summary.New),
		fmt.Sprintf("%d absent", summary.Absent),
		fmt.Sprintf("%d unchanged", summary.Unchanged),
		fmt.Sprintf("%d updated", summary.Updated),
	}
	fmt.Printf("Summary: %s (%d total)\n", strings.Join(parts, ", "), summary.Total)

	// Show data flow change counts if present
	if extensions != nil {
		if dfChanges, ok := extensions["dataFlowChanges"].([]systemDiffDataFlow); ok && len(dfChanges) > 0 {
			added, removed, updated := 0, 0, 0
			for _, df := range dfChanges {
				switch df.State {
				case stateAdded:
					added++
				case stateRemoved:
					removed++
				case stateUpdated:
					updated++
				}
			}
			fmt.Printf("Data Flows: %d added, %d removed, %d updated\n", added, removed, updated)
		}
	}
}

func outputSystemDiffNameOnly(result systemDiffResult) {
	for _, cd := range result.ComponentDiffs {
		if cd.State != diff.StateUnchanged {
			fmt.Println(sanitizeOutput(cd.Name))
		}
	}
}

// outputComponentSummaries prints grouped summaries in human-readable format.
// headerLabel names the first column (e.g. "Component" for --system, "Baseline" for --group-by baseline).
func outputComponentSummaries(summaries []componentSummary, headerLabel string) {
	tbl := NewTable(
		Column{Header: headerLabel},
		Column{Header: "Baselines"},
		Column{Header: "Fixed", Align: AlignRight},
		Column{Header: "Regressed", Align: AlignRight},
		Column{Header: "New", Align: AlignRight},
		Column{Header: "Absent", Align: AlignRight},
		Column{Header: "Unchanged", Align: AlignRight},
		Column{Header: "Old Compliance", Align: AlignRight},
		Column{Header: "New Compliance", Align: AlignRight},
		Column{Header: "Delta", Align: AlignRight},
	)
	for _, cs := range summaries {
		delta := cs.ComplianceDelta
		deltaStr := "0%"
		if delta > 0 {
			deltaStr = fmt.Sprintf("+%.0f%%", delta)
		} else if delta < 0 {
			deltaStr = fmt.Sprintf("%.0f%%", delta)
		}
		tbl.AddRow(
			sanitizeOutput(cs.Name),
			sanitizeOutput(strings.Join(cs.BaselineRefs, ", ")),
			fmt.Sprintf("%d", cs.Summary.Fixed),
			fmt.Sprintf("%d", cs.Summary.Regressed),
			fmt.Sprintf("%d", cs.Summary.New),
			fmt.Sprintf("%d", cs.Summary.Absent),
			fmt.Sprintf("%d", cs.Summary.Unchanged),
			fmt.Sprintf("%.0f%%", cs.OldCompliance),
			fmt.Sprintf("%.0f%%", cs.NewCompliance),
			deltaStr,
		)
	}
	tbl.Render()
}
