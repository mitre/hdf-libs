package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mitre/hdf-cli/pkg/diff/sbom"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
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
		Short: "Compare two HDF results files",
		Long: `Compare two HDF results files and show what changed between them.

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
  hdf diff --sbom old.cdx.json new.cdx.json               # SBOM comparison mode`,
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

	oldResults, newResults, err := loadDiffInputs(oldFile, newFile)
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
func loadDiffInputs(oldFile, newFile string) (hdf.HdfResults, hdf.HdfResults, error) {
	oldData, err := readInputFile(oldFile)
	if err != nil {
		printError(err.Error())
		return hdf.HdfResults{}, hdf.HdfResults{}, err
	}
	oldResults, err := parseHDFResults(oldData)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse old HDF file: %v", err))
		return hdf.HdfResults{}, hdf.HdfResults{}, err
	}
	newData, err := readInputFile(newFile)
	if err != nil {
		printError(err.Error())
		return hdf.HdfResults{}, hdf.HdfResults{}, err
	}
	newResults, err := parseHDFResults(newData)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse new HDF file: %v", err))
		return hdf.HdfResults{}, hdf.HdfResults{}, err
	}
	return oldResults, newResults, nil
}

// renderDiffOutput writes the diff output in the requested format.
func renderDiffOutput(filtered diffResult, flags *diffFlags, oldFile, newFile string) error {
	switch {
	case flags.nameOnly:
		outputDiffNameOnly(filtered)
	case flags.stat:
		outputDiffSummary(filtered.Summary)
	case jsonOutput || flags.format == "json":
		if err := outputDiffJSON(filtered); err != nil {
			return err
		}
	case flags.format == "markdown":
		outputDiffMarkdown(filtered, oldFile, newFile)
		outputComponentSummariesIfPresent(filtered.ComponentSummaries)
	default:
		outputDiffTable(filtered, oldFile, newFile)
		outputComponentSummariesIfPresent(filtered.ComponentSummaries)
	}
	return nil
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
	fmt.Printf("HDF Comparison: %s → %s\n", sanitizeOutput(oldFile), sanitizeOutput(newFile))
	fmt.Println()

	for _, req := range result.Requirements {
		prefix := statePrefix(req.State)
		transition := formatTransition(req)
		stateLabel := fmt.Sprintf("(%s)", req.State)

		titleStr := ""
		if req.Title != "" {
			titleStr = fmt.Sprintf("  %-40s", sanitizeOutput(truncate(req.Title, 40)))
		}

		fmt.Printf("  %s %-10s%s %s  %s\n", prefix, sanitizeOutput(req.ID), titleStr, transition, stateLabel)
	}

	fmt.Println()
	outputDiffSummary(result.Summary)
}

func outputDiffMarkdown(result diffResult, oldFile, newFile string) {
	fmt.Printf("## HDF Comparison: %s → %s\n", sanitizeOutput(oldFile), sanitizeOutput(newFile))
	fmt.Println()

	fmt.Println("| Status | ID | Title | Old Status | New Status | State |")
	fmt.Println("|--------|-----|-------|------------|------------|-------|")

	for _, req := range result.Requirements {
		prefix := statePrefix(req.State)
		title := sanitizeOutput(truncate(req.Title, 40))
		oldStatus := req.OldStatus
		newStatus := req.NewStatus
		if oldStatus == "" {
			oldStatus = "-"
		}
		if newStatus == "" {
			newStatus = "-"
		}
		fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
			prefix, sanitizeOutput(req.ID), title, oldStatus, newStatus, req.State)
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

// statePrefix returns a symbol prefix for the diff state.
func statePrefix(state diffState) string {
	switch state {
	case diffFixed:
		return "+"
	case diffRegressed:
		return "-"
	case diffNew:
		return "+"
	case diffAbsent:
		return "-"
	case diffUpdated:
		return "~"
	case diffUnchanged:
		return " "
	default:
		return " "
	}
}

// formatTransition returns a "old → new" string for the status transition.
func formatTransition(req diffRequirement) string {
	if req.OldStatus != "" && req.NewStatus != "" {
		return fmt.Sprintf("%s → %s", req.OldStatus, req.NewStatus)
	}
	return ""
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

	if jsonOutput || flags.format == "json" {
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
	fmt.Printf("SBOM Comparison: %s → %s\n\n", sanitizeOutput(oldFile), sanitizeOutput(newFile))

	for _, d := range result.PackageDiffs {
		prefix := " "
		switch d.State {
		case "added":
			prefix = "+"
		case "removed":
			prefix = "-"
		case "updated":
			prefix = "~"
		}

		version := ""
		switch d.State {
		case "updated":
			version = fmt.Sprintf("%s → %s", d.OldVersion, d.NewVersion)
		case "added":
			version = d.NewVersion
		case "removed":
			version = d.OldVersion
		}

		fmt.Printf("  %s %-30s %-20s (%s)\n", prefix, sanitizeOutput(d.Name), version, d.State)
	}

	fmt.Printf("\nSummary: %d added, %d removed, %d updated, %d unchanged\n",
		result.Added, result.Removed, result.Updated, result.Unchanged)
}

// outputComponentSummaries prints component summaries in human-readable format.
func outputComponentSummaries(summaries []componentSummary) {
	for _, cs := range summaries {
		refs := strings.Join(cs.BaselineRefs, ", ")
		fmt.Printf("Component: %s (%s)\n", sanitizeOutput(cs.Name), sanitizeOutput(refs))
		fmt.Printf("  Fixed: %d  Regressed: %d  New: %d  Absent: %d  Unchanged: %d\n",
			cs.Summary.Fixed, cs.Summary.Regressed, cs.Summary.New, cs.Summary.Absent, cs.Summary.Unchanged)

		delta := cs.ComplianceDelta
		deltaStr := "no change"
		if delta > 0 {
			deltaStr = fmt.Sprintf("+%.0f%%", delta)
		} else if delta < 0 {
			deltaStr = fmt.Sprintf("%.0f%%", delta)
		}
		fmt.Printf("  Compliance: %.0f%% -> %.0f%% (%s)\n", cs.OldCompliance, cs.NewCompliance, deltaStr)
		fmt.Println()
	}
}
