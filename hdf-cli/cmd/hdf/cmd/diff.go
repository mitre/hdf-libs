package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mitre/hdf-cli/pkg/diff/sbom"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
	validators "github.com/mitre/hdf-validators/go"
	"github.com/spf13/cobra"
)

// Exit code constants for diff command.
//
// Basic mode (--exit-code): GNU diff compatible.
const (
	exitIdentical   = 0
	exitDifferences = 1
	exitError       = 2
)

// Detailed mode (--detailed-exitcode): nuanced security outcomes.
const (
	exitFixesOnly       = 10
	exitRegressionsOnly = 11
	exitMixed           = 12
	exitBaselineChanged = 13
	exitDriftOnly       = 14
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

// diffState represents the classification of a requirement between two scans.
type diffState string

const (
	diffFixed     diffState = "fixed"
	diffRegressed diffState = "regressed"
	diffUnchanged diffState = "unchanged"
	diffUpdated   diffState = "updated"
	diffNew       diffState = "new"
	diffAbsent    diffState = "absent"

	// Output format and SBOM state constants.
	formatJSON   = "json"
	stateAdded   = "added"
	stateRemoved = "removed"
	stateUpdated = "updated"
)

// diffRequirement holds the comparison result for a single requirement.
type diffRequirement struct {
	ID        string    `json:"id"`
	State     diffState `json:"state"`
	OldStatus string    `json:"oldStatus,omitempty"`
	NewStatus string    `json:"newStatus,omitempty"`
	Title     string    `json:"title,omitempty"`
	Baseline  string    `json:"baseline,omitempty"` // baseline name this requirement belongs to
}

// diffSummary holds the aggregate counts for a comparison.
type diffSummary struct {
	Total     int `json:"total"`
	Fixed     int `json:"fixed"`
	Regressed int `json:"regressed"`
	New       int `json:"new"`
	Absent    int `json:"absent"`
	Unchanged int `json:"unchanged"`
	Updated   int `json:"updated"`
}

// componentSummary holds per-component compliance information for system-aware diffs.
type componentSummary struct {
	Name            string      `json:"name"`
	BaselineRefs    []string    `json:"baselineRefs"`
	Summary         diffSummary `json:"summary"`
	OldCompliance   float64     `json:"oldCompliance"`
	NewCompliance   float64     `json:"newCompliance"`
	ComplianceDelta float64     `json:"complianceDelta"`
}

// diffResult is the full output of a diff operation.
type diffResult struct {
	FormatVersion      string             `json:"formatVersion"`
	ComparisonMode     string             `json:"comparisonMode"`
	Summary            diffSummary        `json:"summary"`
	Requirements       []diffRequirement  `json:"requirements"`
	ComponentSummaries []componentSummary `json:"componentSummaries,omitempty"`
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

	result := compareHDFResults(oldResults, newResults)

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
func loadDiffInputs(oldFile, newFile string) (hdf.HdfResults, hdf.HdfResults, error) {
	oldData, err := readInputFile(oldFile)
	if err != nil {
		printError(err.Error())
		return hdf.HdfResults{}, hdf.HdfResults{}, err
	}
	newData, err := readInputFile(newFile)
	if err != nil {
		printError(err.Error())
		return hdf.HdfResults{}, hdf.HdfResults{}, err
	}
	return loadDiffInputsFromData(oldData, newData, oldFile, newFile)
}

// loadDiffInputsFromData parses pre-read data into HDF results.
func loadDiffInputsFromData(oldData, newData []byte, oldFile, newFile string) (hdf.HdfResults, hdf.HdfResults, error) {
	oldResults, err := parseHDFResults(oldData)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse old HDF file (%s): %v", oldFile, err))
		return hdf.HdfResults{}, hdf.HdfResults{}, err
	}
	newResults, err := parseHDFResults(newData)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse new HDF file (%s): %v", newFile, err))
		return hdf.HdfResults{}, hdf.HdfResults{}, err
	}
	return oldResults, newResults, nil
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
		outputComponentSummariesIfPresent(filtered.ComponentSummaries)
	default:
		outputDiffTable(display, oldFile, newFile)
		outputComponentSummariesIfPresent(filtered.ComponentSummaries)
	}
	return nil
}

// stripUnchanged returns a copy of the result with unchanged requirements removed.
// The summary is preserved from the original (full counts).
func stripUnchanged(result diffResult) diffResult {
	var changed []diffRequirement
	for _, req := range result.Requirements {
		if req.State != diffUnchanged {
			changed = append(changed, req)
		}
	}
	return diffResult{
		FormatVersion:      result.FormatVersion,
		ComparisonMode:     result.ComparisonMode,
		Summary:            result.Summary, // keep full summary
		Requirements:       changed,
		ComponentSummaries: result.ComponentSummaries,
	}
}

// outputComponentSummariesIfPresent prints component summaries when they exist.
func outputComponentSummariesIfPresent(summaries []componentSummary) {
	if len(summaries) > 0 {
		fmt.Println()
		outputComponentSummaries(summaries)
	}
}

// computeDiffExitCode returns an exit code error if --exit-code or --detailed-exitcode is set.
func computeDiffExitCode(summary diffSummary, flags *diffFlags) error {
	if flags.detailedExitCode {
		code := computeDetailedExitCode(summary)
		if code != 0 {
			return &exitCodeError{code: code, message: fmt.Sprintf("detailed exit code: %d", code)}
		}
		return nil
	}
	// Basic exit codes are always active (GNU diff convention):
	// 0 = identical, 1 = differences found
	code := computeBasicExitCode(summary)
	if code != 0 {
		return &exitCodeError{code: code, message: "differences found"}
	}
	return nil
}

// compareHDFResults compares two HDF results documents using temporal mode
// with exact-ID matching.
func compareHDFResults(oldResults, newResults hdf.HdfResults) diffResult {
	// Build maps of requirement ID → requirement
	oldMap := buildRequirementMap(oldResults)
	newMap := buildRequirementMap(newResults)

	// Build baseline membership maps (requirement ID → baseline name)
	oldBaselineMap := buildRequirementBaselineMap(oldResults)
	newBaselineMap := buildRequirementBaselineMap(newResults)

	var requirements []diffRequirement

	// Track all IDs seen
	allIDs := make(map[string]bool)
	for id := range oldMap {
		allIDs[id] = true
	}
	for id := range newMap {
		allIDs[id] = true
	}

	// Sort IDs for deterministic output
	sortedIDs := make([]string, 0, len(allIDs))
	for id := range allIDs {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	for _, id := range sortedIDs {
		oldReq, inOld := oldMap[id]
		newReq, inNew := newMap[id]

		var dr diffRequirement
		dr.ID = id

		// Resolve baseline name: prefer new, fall back to old
		if b, ok := newBaselineMap[id]; ok {
			dr.Baseline = b
		} else if b, ok := oldBaselineMap[id]; ok {
			dr.Baseline = b
		}

		switch {
		case inOld && !inNew:
			// Absent - only in old
			dr.State = diffAbsent
			dr.OldStatus = determineControlStatus(oldReq)
			dr.Title = getRequirementTitle(oldReq)

		case !inOld && inNew:
			// New - only in new
			dr.State = diffNew
			dr.NewStatus = determineControlStatus(newReq)
			dr.Title = getRequirementTitle(newReq)

		default:
			// Present in both - classify the change
			oldStatus := determineControlStatus(oldReq)
			newStatus := determineControlStatus(newReq)
			dr.OldStatus = oldStatus
			dr.NewStatus = newStatus
			dr.Title = getRequirementTitle(newReq)
			dr.State = classifyChange(oldStatus, newStatus)
		}

		requirements = append(requirements, dr)
	}

	return diffResult{
		FormatVersion:  "1.0.0",
		ComparisonMode: "temporal",
		Summary:        buildDiffSummary(requirements),
		Requirements:   requirements,
	}
}

// buildRequirementMap collects all requirements across baselines into a map keyed by ID.
func buildRequirementMap(results hdf.HdfResults) map[string]hdf.EvaluatedRequirement {
	reqMap := make(map[string]hdf.EvaluatedRequirement)
	for _, baseline := range results.Baselines {
		for _, req := range baseline.Requirements {
			reqMap[req.ID] = req
		}
	}
	return reqMap
}

// buildRequirementBaselineMap returns a map from requirement ID to baseline name.
func buildRequirementBaselineMap(results hdf.HdfResults) map[string]string {
	m := make(map[string]string)
	for _, baseline := range results.Baselines {
		for _, req := range baseline.Requirements {
			m[req.ID] = baseline.Name
		}
	}
	return m
}

// classifyChange determines the diff state based on old and new status values.
func classifyChange(oldStatus, newStatus string) diffState {
	if oldStatus == newStatus {
		return diffUnchanged
	}

	oldFailing := isFailingStatus(oldStatus)
	oldPassing := isPassingStatus(oldStatus)
	newFailing := isFailingStatus(newStatus)
	newPassing := isPassingStatus(newStatus)

	switch {
	case oldFailing && newPassing:
		return diffFixed
	case oldPassing && newFailing:
		return diffRegressed
	default:
		return diffUpdated
	}
}

// isPassingStatus returns true if the status is considered passing.
func isPassingStatus(status string) bool {
	return status == StatusPassed
}

// isFailingStatus returns true if the status is considered failing.
func isFailingStatus(status string) bool {
	return status == StatusFailed || status == StatusError || status == StatusNotReviewed
}

// getRequirementTitle returns the title of a requirement, or empty string if nil.
func getRequirementTitle(req hdf.EvaluatedRequirement) string {
	if req.Title != nil {
		return *req.Title
	}
	return ""
}

// buildDiffSummary computes summary counts from a slice of requirements.
func buildDiffSummary(requirements []diffRequirement) diffSummary {
	summary := diffSummary{Total: len(requirements)}
	for _, req := range requirements {
		switch req.State {
		case diffFixed:
			summary.Fixed++
		case diffRegressed:
			summary.Regressed++
		case diffNew:
			summary.New++
		case diffAbsent:
			summary.Absent++
		case diffUnchanged:
			summary.Unchanged++
		case diffUpdated:
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

	allowed := map[diffState]bool{
		diffFixed:     flags.fixed,
		diffRegressed: flags.regressed,
		diffNew:       flags.newOnly,
		diffAbsent:    flags.absent,
	}

	var filtered []diffRequirement
	for _, req := range result.Requirements {
		if allowed[req.State] {
			filtered = append(filtered, req)
		}
	}

	return diffResult{
		FormatVersion:      result.FormatVersion,
		ComparisonMode:     result.ComparisonMode,
		Summary:            buildDiffSummary(filtered),
		Requirements:       filtered,
		ComponentSummaries: result.ComponentSummaries,
	}
}

// --- Exit code computation ---

// computeBasicExitCode returns 0 for identical, 1 for any differences (GNU diff compatible).
func computeBasicExitCode(summary diffSummary) int {
	if summary.Total == summary.Unchanged {
		return exitIdentical
	}
	return exitDifferences
}

// computeDetailedExitCode returns a nuanced exit code based on what changed.
//
// Priority order: mixed(12) > regressions(11) > fixes(10) > baseline(13) > drift(14).
func computeDetailedExitCode(summary diffSummary) int {
	if summary.Total == summary.Unchanged {
		return exitIdentical
	}

	// Mixed: both fixes and regressions
	if summary.Regressed > 0 && summary.Fixed > 0 {
		return exitMixed
	}

	// Regressions only (no fixes)
	if summary.Regressed > 0 {
		return exitRegressionsOnly
	}

	// Fixes only (no regressions)
	if summary.Fixed > 0 {
		return exitFixesOnly
	}

	// Baseline changes: new or absent controls (but no status changes)
	if summary.New > 0 || summary.Absent > 0 {
		return exitBaselineChanged
	}

	// Everything else is metadata drift
	return exitDriftOnly
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

	tbl := NewTable(
		Column{Header: "ID"},
		Column{Header: "Title"},
		Column{Header: "Old Status"},
		Column{Header: "New Status"},
		Column{Header: "State"},
	)
	for _, req := range result.Requirements {
		oldStatus := req.OldStatus
		newStatus := req.NewStatus
		if oldStatus == "" {
			oldStatus = "-"
		}
		if newStatus == "" {
			newStatus = "-"
		}
		tbl.AddRow(
			sanitizeOutput(req.ID),
			sanitizeOutput(truncate(req.Title, 40)),
			oldStatus,
			newStatus,
			string(req.State),
		)
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

	fmt.Println("| ID | Title | Old Status | New Status | State |")
	fmt.Println("|----|-------|------------|------------|-------|")

	for _, req := range result.Requirements {
		title := sanitizeOutput(truncate(req.Title, 40))
		oldStatus := req.OldStatus
		newStatus := req.NewStatus
		if oldStatus == "" {
			oldStatus = "-"
		}
		if newStatus == "" {
			newStatus = "-"
		}
		fmt.Printf("| %s | %s | %s | %s | %s |\n",
			sanitizeOutput(req.ID), title, oldStatus, newStatus, req.State)
	}

	fmt.Println()
	outputDiffSummary(result.Summary)
}

func outputDiffSummary(summary diffSummary) {
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
	for _, req := range result.Requirements {
		if req.State != diffUnchanged {
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

// applyComponentGrouping applies either system-aware or label-based grouping to the diff result.
func applyComponentGrouping(flags *diffFlags, oldResults, newResults hdf.HdfResults, result *diffResult) error {
	if flags.system != "" {
		summaries, err := applySystemGrouping(flags.system, oldResults, newResults, *result)
		if err != nil {
			return err
		}
		result.ComponentSummaries = summaries
	}
	if flags.groupBy != "" {
		result.ComponentSummaries = applyGroupBy(flags.groupBy, oldResults, newResults, *result)
	}
	return nil
}

// applySystemGrouping reads the system document and groups diff requirements by component.
// Components reference baselines via baselineRefs; requirements are matched to components
// by their baseline membership.
func applySystemGrouping(
	systemPath string,
	oldResults, newResults hdf.HdfResults,
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
	oldResults, newResults hdf.HdfResults,
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
		for _, req := range result.Requirements {
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
func computeBaselineCompliance(results hdf.HdfResults, baselineSet map[string]bool) float64 {
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

// applyGroupBy groups diff requirements by a label key. Currently supports "baseline"
// as the group-by key, which groups by the baseline name each requirement belongs to.
func applyGroupBy(
	groupKey string,
	oldResults, newResults hdf.HdfResults,
	result diffResult,
) []componentSummary {
	if groupKey != groupByBaselineKey {
		// For label-based grouping, prefix "labels." is stripped
		groupKey = strings.TrimPrefix(groupKey, "labels.")
	}

	if groupKey == groupByBaselineKey {
		return groupByBaselineName(oldResults, newResults, result)
	}

	// For arbitrary label keys, group by baseline labels
	return groupByLabel(groupKey, oldResults, newResults, result)
}

// groupByBaselineName groups requirements by their baseline name.
func groupByBaselineName(
	oldResults, newResults hdf.HdfResults,
	result diffResult,
) []componentSummary {
	// Collect unique baseline names
	groups := make(map[string][]diffRequirement)
	for _, req := range result.Requirements {
		if req.Baseline == "" {
			continue
		}
		groups[req.Baseline] = append(groups[req.Baseline], req)
	}

	// Sort group names for deterministic output
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)

	var summaries []componentSummary
	for _, name := range names {
		reqs := groups[name]
		compSummary := buildDiffSummary(reqs)

		baselineSet := map[string]bool{name: true}
		oldCompliance := computeBaselineCompliance(oldResults, baselineSet)
		newCompliance := computeBaselineCompliance(newResults, baselineSet)

		summaries = append(summaries, componentSummary{
			Name:            name,
			BaselineRefs:    []string{name},
			Summary:         compSummary,
			OldCompliance:   oldCompliance,
			NewCompliance:   newCompliance,
			ComplianceDelta: newCompliance - oldCompliance,
		})
	}

	return summaries
}

// groupByLabel groups requirements by a label value found on baselines.
// It looks for the label key in baseline extensions.labels or top-level baseline metadata.
func groupByLabel(
	labelKey string,
	oldResults, newResults hdf.HdfResults,
	result diffResult,
) []componentSummary {
	// Build a map from baseline name → label value by examining both old and new results
	baselineLabelMap := make(map[string]string)
	for _, results := range []hdf.HdfResults{oldResults, newResults} {
		for _, baseline := range results.Baselines {
			if baseline.Extensions != nil {
				if labels, ok := baseline.Extensions["labels"].(map[string]interface{}); ok {
					if val, ok := labels[labelKey].(string); ok {
						baselineLabelMap[baseline.Name] = val
					}
				}
			}
		}
	}

	// Group requirements by their baseline's label value
	groups := make(map[string][]diffRequirement)
	for _, req := range result.Requirements {
		labelVal, ok := baselineLabelMap[req.Baseline]
		if !ok {
			labelVal = "(unlabeled)"
		}
		groups[labelVal] = append(groups[labelVal], req)
	}

	// Sort group names
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)

	var summaries []componentSummary
	for _, name := range names {
		reqs := groups[name]
		compSummary := buildDiffSummary(reqs)

		// Collect baselines for this group
		baselineSet := make(map[string]bool)
		for _, req := range reqs {
			if req.Baseline != "" {
				baselineSet[req.Baseline] = true
			}
		}

		refs := make([]string, 0, len(baselineSet))
		for b := range baselineSet {
			refs = append(refs, b)
		}
		sort.Strings(refs)

		oldCompliance := computeBaselineCompliance(oldResults, baselineSet)
		newCompliance := computeBaselineCompliance(newResults, baselineSet)

		summaries = append(summaries, componentSummary{
			Name:            name,
			BaselineRefs:    refs,
			Summary:         compSummary,
			OldCompliance:   oldCompliance,
			NewCompliance:   newCompliance,
			ComplianceDelta: newCompliance - oldCompliance,
		})
	}

	return summaries
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

	result, err := sbom.DiffSBOMs(oldData, newData)
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
func outputSbomJSON(result *sbom.DiffResult) error {
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

// outputSbomTable renders the SBOM diff result as a human-readable table.
func outputSbomTable(result *sbom.DiffResult, oldFile, newFile string) {
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
	State        diffState               `json:"state"`
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
	Summary        diffSummary            `json:"summary"`
	ComponentDiffs []systemDiffComponent  `json:"componentDiffs"`
	Extensions     map[string]interface{} `json:"extensions,omitempty"`
}

// systemComponentTrackedFields are the fields tracked for component-level changes.
var systemComponentTrackedFields = []string{
	"type", "description", "baselineRefs", "inputOverrides", "sbomRef", "targetSelector",
}

// systemTopLevelFields are the fields tracked for system-level changes.
var systemTopLevelFields = []string{
	"authorizationStatus", "categorizationLevel", "description",
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

	result := compareSystemDocuments(oldSys, newSys)

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

// compareSystemDocuments compares two system documents and produces a systemDiffResult.
func compareSystemDocuments(oldSys, newSys map[string]interface{}) systemDiffResult {
	oldComponents := toMapSlice(oldSys["components"])
	newComponents := toMapSlice(newSys["components"])

	// Match components: componentId first, then name
	pairs := matchSystemComponents(oldComponents, newComponents)
	var componentDiffs []systemDiffComponent

	for _, p := range pairs {
		switch {
		case p.oldComp != nil && p.newComp != nil:
			changes := computeFieldChanges(p.oldComp, p.newComp, systemComponentTrackedFields)
			state := diffUnchanged
			if len(changes) > 0 {
				state = diffUpdated
			}
			componentDiffs = append(componentDiffs, systemDiffComponent{
				Name: p.name, State: state, FieldChanges: changes,
			})
		case p.oldComp != nil:
			componentDiffs = append(componentDiffs, systemDiffComponent{
				Name: p.name, State: diffAbsent,
			})
		case p.newComp != nil:
			componentDiffs = append(componentDiffs, systemDiffComponent{
				Name: p.name, State: diffNew,
			})
		}
	}

	sort.Slice(componentDiffs, func(i, j int) bool {
		return componentDiffs[i].Name < componentDiffs[j].Name
	})

	// Build summary
	summary := buildSystemDiffSummary(componentDiffs)

	// Extensions: system field changes + data flow changes
	extensions := make(map[string]interface{})

	sysFieldChanges := computeFieldChanges(oldSys, newSys, systemTopLevelFields)
	if len(sysFieldChanges) > 0 {
		extensions["systemFieldChanges"] = sysFieldChanges
	}

	dataFlowChanges := diffSystemDataFlows(oldSys, newSys)
	if len(dataFlowChanges) > 0 {
		extensions["dataFlowChanges"] = dataFlowChanges
	}

	var ext map[string]interface{}
	if len(extensions) > 0 {
		ext = extensions
	}

	return systemDiffResult{
		FormatVersion:  "1.0.0",
		ComparisonMode: "systemDrift",
		Summary:        summary,
		ComponentDiffs: componentDiffs,
		Extensions:     ext,
	}
}

// systemComponentPair holds a matched pair of old/new components.
type systemComponentPair struct {
	name    string
	oldComp map[string]interface{}
	newComp map[string]interface{}
}

// matchSystemComponents matches components by componentId first, then by name.
func matchSystemComponents(
	oldComponents, newComponents []map[string]interface{},
) []systemComponentPair {
	matched := make(map[int]bool)    // indices of matched new components
	oldMatched := make(map[int]bool) // indices of matched old components
	var pairs []systemComponentPair

	// First pass: match by componentId
	matchByComponentID(oldComponents, newComponents, &pairs, oldMatched, matched)

	// Second pass: match remaining by name
	matchByName(oldComponents, newComponents, &pairs, oldMatched, matched)

	// Collect unmatched as absent/new
	collectUnmatched(oldComponents, newComponents, &pairs, oldMatched, matched)

	return pairs
}

// matchByComponentID matches old and new components by their componentId field.
func matchByComponentID(
	oldComponents, newComponents []map[string]interface{},
	pairs *[]systemComponentPair, oldMatched, newMatched map[int]bool,
) {
	newByID := make(map[string]int)
	for i, c := range newComponents {
		if id, ok := c["componentId"].(string); ok && id != "" {
			newByID[id] = i
		}
	}

	for i, oldC := range oldComponents {
		oldID, _ := oldC["componentId"].(string)
		if oldID == "" {
			continue
		}
		if ni, ok := newByID[oldID]; ok {
			newC := newComponents[ni]
			name := stringVal(newC, "name")
			if name == "" {
				name = stringVal(oldC, "name")
			}
			if name == "" {
				name = oldID
			}
			*pairs = append(*pairs, systemComponentPair{name: name, oldComp: oldC, newComp: newC})
			newMatched[ni] = true
			oldMatched[i] = true
		}
	}
}

// matchByName matches remaining unmatched components by name.
func matchByName(
	oldComponents, newComponents []map[string]interface{},
	pairs *[]systemComponentPair, oldMatched, newMatched map[int]bool,
) {
	newByName := make(map[string]int)
	for i, c := range newComponents {
		if newMatched[i] {
			continue
		}
		if name, ok := c["name"].(string); ok && name != "" {
			newByName[name] = i
		}
	}

	for i, oldC := range oldComponents {
		if oldMatched[i] {
			continue
		}
		name := stringVal(oldC, "name")
		if name == "" {
			continue
		}
		if ni, ok := newByName[name]; ok {
			*pairs = append(*pairs, systemComponentPair{name: name, oldComp: oldC, newComp: newComponents[ni]})
			newMatched[ni] = true
			oldMatched[i] = true
			delete(newByName, name)
		}
	}
}

// collectUnmatched adds unmatched old components (absent) and new components (new) to pairs.
func collectUnmatched(
	oldComponents, newComponents []map[string]interface{},
	pairs *[]systemComponentPair, oldMatched, newMatched map[int]bool,
) {
	for i, oldC := range oldComponents {
		if oldMatched[i] {
			continue
		}
		name := stringVal(oldC, "name")
		if name == "" {
			name = fmt.Sprintf("component-%d", i)
		}
		*pairs = append(*pairs, systemComponentPair{name: name, oldComp: oldC})
	}

	for i, newC := range newComponents {
		if newMatched[i] {
			continue
		}
		name := stringVal(newC, "name")
		if name == "" {
			name = fmt.Sprintf("component-%d", i)
		}
		*pairs = append(*pairs, systemComponentPair{name: name, newComp: newC})
	}
}

// computeFieldChanges computes field-level diffs for tracked fields using JSON comparison.
func computeFieldChanges(
	oldObj, newObj map[string]interface{},
	trackedFields []string,
) []systemDiffFieldChange {
	var changes []systemDiffFieldChange

	for _, field := range trackedFields {
		oldVal, oldOK := oldObj[field]
		newVal, newOK := newObj[field]

		oldJSON, _ := json.Marshal(oldVal)
		newJSON, _ := json.Marshal(newVal)

		if string(oldJSON) != string(newJSON) {
			switch {
			case !oldOK && newOK:
				changes = append(changes, systemDiffFieldChange{Op: "add", Path: field, NewValue: newVal})
			case oldOK && !newOK:
				changes = append(changes, systemDiffFieldChange{Op: "remove", Path: field, OldValue: oldVal})
			default:
				changes = append(changes, systemDiffFieldChange{Op: "replace", Path: field, OldValue: oldVal, NewValue: newVal})
			}
		}
	}

	return changes
}

// diffSystemDataFlows diffs data flows between two system documents.
// Flows are keyed by from→to.
func diffSystemDataFlows(oldSys, newSys map[string]interface{}) []systemDiffDataFlow {
	oldFlows := toMapSlice(oldSys["dataFlows"])
	newFlows := toMapSlice(newSys["dataFlows"])

	if len(oldFlows) == 0 && len(newFlows) == 0 {
		return nil
	}

	flowKey := func(f map[string]interface{}) string {
		from, _ := f["from"].(string)
		to, _ := f["to"].(string)
		if to == "" {
			toJSON, _ := json.Marshal(f["to"])
			to = string(toJSON)
		}
		return from + "→" + to
	}

	oldMap := make(map[string]map[string]interface{})
	for _, f := range oldFlows {
		oldMap[flowKey(f)] = f
	}
	newMap := make(map[string]map[string]interface{})
	for _, f := range newFlows {
		newMap[flowKey(f)] = f
	}

	allKeys := make(map[string]bool)
	for k := range oldMap {
		allKeys[k] = true
	}
	for k := range newMap {
		allKeys[k] = true
	}

	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	var changes []systemDiffDataFlow
	for _, key := range sortedKeys {
		oldF, inOld := oldMap[key]
		newF, inNew := newMap[key]

		switch {
		case inOld && inNew:
			oldJSON, _ := json.Marshal(oldF)
			newJSON, _ := json.Marshal(newF)
			if string(oldJSON) != string(newJSON) {
				changes = append(changes, systemDiffDataFlow{State: stateUpdated, Flow: newF})
			}
		case inOld:
			changes = append(changes, systemDiffDataFlow{State: stateRemoved, Flow: oldF})
		case inNew:
			changes = append(changes, systemDiffDataFlow{State: stateAdded, Flow: newF})
		}
	}

	return changes
}

// buildSystemDiffSummary computes summary counts from component diffs.
func buildSystemDiffSummary(diffs []systemDiffComponent) diffSummary {
	summary := diffSummary{Total: len(diffs)}
	for _, d := range diffs {
		switch d.State { //nolint:exhaustive // system diffs only produce new/absent/unchanged/updated
		case diffNew:
			summary.New++
		case diffAbsent:
			summary.Absent++
		case diffUnchanged:
			summary.Unchanged++
		case diffUpdated:
			summary.Updated++
		}
	}
	return summary
}

// computeSystemDiffExitCode returns an exit code for system diffs.
func computeSystemDiffExitCode(summary diffSummary, flags *diffFlags) error {
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
		if cd.State != diffUnchanged {
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

func outputSystemDiffSummary(summary diffSummary, extensions map[string]interface{}) {
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
		if cd.State != diffUnchanged {
			fmt.Println(sanitizeOutput(cd.Name))
		}
	}
}

// toMapSlice safely converts an interface{} to []map[string]interface{}.
func toMapSlice(v interface{}) []map[string]interface{} {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

// stringVal extracts a string value from a map, returning "" if not present or not a string.
//
//nolint:unparam // key varies by call site intent; extracting only "name" is incidental
func stringVal(m map[string]interface{}, key string) string {
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return v
}

// outputComponentSummaries prints component summaries in human-readable format.
func outputComponentSummaries(summaries []componentSummary) {
	tbl := NewTable(
		Column{Header: "Component"},
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
