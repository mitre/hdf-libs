package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

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

// diffResult is the full output of a diff operation.
type diffResult struct {
	FormatVersion  string            `json:"formatVersion"`
	ComparisonMode string            `json:"comparisonMode"`
	Summary        diffSummary       `json:"summary"`
	Requirements   []diffRequirement `json:"requirements"`
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
  hdf diff scan-before.json scan-after.json --name-only   # changed requirement IDs only`,
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

	return cmd
}

func runDiff(_ *cobra.Command, args []string, flags *diffFlags) error {
	oldFile := args[0]
	newFile := args[1]

	// Read and parse old file
	oldData, err := readInputFile(oldFile)
	if err != nil {
		printError(err.Error())
		return err
	}

	oldResults, err := parseHDFResults(oldData)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse old HDF file: %v", err))
		return err
	}

	// Read and parse new file
	newData, err := readInputFile(newFile)
	if err != nil {
		printError(err.Error())
		return err
	}

	newResults, err := parseHDFResults(newData)
	if err != nil {
		printError(fmt.Sprintf("Failed to parse new HDF file: %v", err))
		return err
	}

	// Perform comparison
	result := compareHDFResults(oldResults, newResults)

	// Apply filters
	filtered := applyDiffFilters(result, flags)

	// --quiet implies --exit-code and suppresses all output
	if flags.quiet {
		flags.exitCode = true
	}

	// Output (unless --quiet)
	if !flags.quiet {
		switch {
		case flags.nameOnly:
			outputDiffNameOnly(filtered)
		case flags.stat:
			outputDiffSummary(result.Summary)
		case jsonOutput || flags.format == "json":
			if err := outputDiffJSON(filtered); err != nil {
				return err
			}
		case flags.format == "markdown":
			outputDiffMarkdown(filtered, oldFile, newFile)
		default:
			outputDiffTable(filtered, oldFile, newFile)
		}
	}

	// Exit code handling: --detailed-exitcode takes precedence over --exit-code.
	if flags.detailedExitCode {
		code := computeDetailedExitCode(result.Summary)
		if code != 0 {
			return &exitCodeError{code: code, message: fmt.Sprintf("detailed exit code: %d", code)}
		}
		return nil
	}

	if flags.exitCode {
		code := computeBasicExitCode(result.Summary)
		if code != 0 {
			return &exitCodeError{code: code, message: "differences found"}
		}
		return nil
	}

	return nil
}

// compareHDFResults compares two HDF results documents using temporal mode
// with exact-ID matching.
func compareHDFResults(oldResults, newResults hdf.HdfResults) diffResult {
	// Build maps of requirement ID → requirement
	oldMap := buildRequirementMap(oldResults)
	newMap := buildRequirementMap(newResults)

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
		FormatVersion:  result.FormatVersion,
		ComparisonMode: result.ComparisonMode,
		Summary:        buildDiffSummary(filtered),
		Requirements:   filtered,
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
