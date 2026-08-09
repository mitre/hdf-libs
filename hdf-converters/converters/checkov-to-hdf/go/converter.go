package checkov

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// CheckovReport is the top-level checkov JSON output structure for a single framework.
type CheckovReport struct {
	CheckType string         `json:"check_type"`
	Results   CheckovResults `json:"results"`
	Summary   CheckovSummary `json:"summary"`
}

// CheckovResults holds the categorized check results.
type CheckovResults struct {
	PassedChecks  []CheckovCheck `json:"passed_checks"`
	FailedChecks  []CheckovCheck `json:"failed_checks"`
	SkippedChecks []CheckovCheck `json:"skipped_checks"`
}

// CheckovSummary holds scan summary metadata.
type CheckovSummary struct {
	Passed         int    `json:"passed"`
	Failed         int    `json:"failed"`
	Skipped        int    `json:"skipped"`
	ParsingErrors  int    `json:"parsing_errors"`
	ResourceCount  int    `json:"resource_count"`
	CheckovVersion string `json:"checkov_version"`
}

// CheckovCheck represents a single check result from checkov.
type CheckovCheck struct {
	CheckID       string             `json:"check_id"`
	BcCheckID     *string            `json:"bc_check_id"`
	CheckName     string             `json:"check_name"`
	CheckResult   CheckovCheckResult `json:"check_result"`
	Severity      *string            `json:"severity"`
	FilePath      string             `json:"file_path"`
	FileLineRange []int              `json:"file_line_range"`
	Resource      string             `json:"resource"`
	Guideline     *string            `json:"guideline"`
	CodeBlock     json.RawMessage    `json:"code_block"`
	CheckClass    string             `json:"check_class"`
}

// CheckovCheckResult holds the check status and optional suppression comment.
type CheckovCheckResult struct {
	Result          string `json:"result"`
	SuppressComment string `json:"suppress_comment"`
}

// mapStatus maps checkov result strings to HDF ResultStatus.
func mapStatus(result string) hdf.ResultStatus {
	switch strings.ToUpper(result) {
	case "PASSED":
		return hdf.Passed
	case "FAILED":
		return hdf.Failed
	case "SKIPPED":
		return hdf.NotReviewed
	default:
		return hdf.NotReviewed
	}
}

// getImpact maps checkov severity strings to HDF impact values.
func getImpact(severity *string) float64 {
	if severity == nil {
		return 0.5
	}
	return hdfutil.SeverityToImpact(*severity, 0.5)
}

// formatCodeDesc builds the code_desc string for a result.
func formatCodeDesc(check CheckovCheck) string {
	return fmt.Sprintf("Resource: %s\nFile: %s (lines %s)",
		check.Resource, check.FilePath, formatLineRange(check.FileLineRange))
}

// renderCodeBlock renders checkov's code_block ([[lineno, "source"], ...]) into a
// readable, line-numbered source snippet for the Heimdall CODE tab. Returns "" when
// the code_block is absent or unparseable so the caller can omit requirement.code.
func renderCodeBlock(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return ""
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		var pair []json.RawMessage
		if err := json.Unmarshal(entry, &pair); err != nil || len(pair) < 2 {
			continue // skip a non-array or short entry, matching the TS renderer
		}
		var lineno int
		var src string
		_ = json.Unmarshal(pair[0], &lineno)
		_ = json.Unmarshal(pair[1], &src)
		lines = append(lines, fmt.Sprintf("%d %s", lineno, strings.TrimSuffix(src, "\n")))
	}
	return strings.Join(lines, "\n")
}

// formatLineRange renders the line range as a JSON array literal ("[26,49]").
// Go's %v on a slice would emit a space-separated Go-ism instead.
func formatLineRange(lines []int) string {
	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = strconv.Itoa(l)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// checkToResult converts a single CheckovCheck into an HDF RequirementResult.
func checkToResult(check CheckovCheck, now time.Time) hdf.RequirementResult {
	status := mapStatus(check.CheckResult.Result)
	codeDesc := formatCodeDesc(check)

	var message *string
	if status == hdf.NotReviewed && check.CheckResult.SuppressComment != "" {
		msg := check.CheckResult.SuppressComment
		message = &msg
	}

	return hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc,
		Message:   message,
		StartTime: now,
	}
}

// checkWithType pairs a check with the check_type of the report it came
// from, so requirement tags can carry the per-finding scan scope.
type checkWithType struct {
	check     CheckovCheck
	checkType string
}

// groupByCheckID groups checks by check_id, preserving insertion order.
func groupByCheckID(checks []checkWithType) ([]string, map[string][]checkWithType) {
	order := []string{}
	groups := map[string][]checkWithType{}
	for _, c := range checks {
		if _, seen := groups[c.check.CheckID]; !seen {
			order = append(order, c.check.CheckID)
		}
		groups[c.check.CheckID] = append(groups[c.check.CheckID], c)
	}
	return order, groups
}

// checkTypesOf collects the unique, sorted check_types of a group.
func checkTypesOf(checks []checkWithType) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range checks {
		if c.checkType != "" && !seen[c.checkType] {
			seen[c.checkType] = true
			out = append(out, c.checkType)
		}
	}
	sort.Strings(out)
	return out
}

// buildRequirement converts a group of checks sharing a check_id into one EvaluatedRequirement.
func buildRequirement(checkID string, group []checkWithType, now time.Time) hdf.EvaluatedRequirement {
	checks := make([]CheckovCheck, len(group))
	for i, c := range group {
		checks[i] = c.check
	}
	rep := checks[0]

	nist := make([]string, len(shared.DefaultStaticAnalysisNIST))
	copy(nist, shared.DefaultStaticAnalysisNIST)

	tags := map[string]interface{}{
		"nist": nist,
	}
	// The scan scope (which framework's report produced this finding) is
	// requirement-level data, not tool metadata.
	if types := checkTypesOf(group); len(types) > 0 {
		tags["check_type"] = types
	}
	// Bridgecrew check identifier (e.g. "BC_AWS_S3_16"); omit when null/absent.
	if rep.BcCheckID != nil && *rep.BcCheckID != "" {
		tags["bc_check_id"] = *rep.BcCheckID
	}

	descriptions := []hdf.Description{
		{Label: "default", Data: rep.CheckName},
	}
	if rep.Guideline != nil && *rep.Guideline != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "check",
			Data:  *rep.Guideline,
		})
	}

	results := make([]hdf.RequirementResult, len(checks))
	for i, check := range checks {
		results[i] = checkToResult(check, now)
	}

	title := rep.CheckName
	req := hdf.EvaluatedRequirement{
		ID:                 checkID,
		Title:              &title,
		Impact:             getImpact(rep.Severity),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
	if code := renderCodeBlock(rep.CodeBlock); code != "" {
		req.Code = &code
	}
	return req
}

// parseInput parses checkov JSON which can be either a single object or an array of objects.
func parseInput(input []byte) ([]CheckovReport, error) {
	input = []byte(strings.TrimSpace(string(input)))
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// Try array first
	if input[0] == '[' {
		var reports []CheckovReport
		if err := json.Unmarshal(input, &reports); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
		return reports, nil
	}

	// Try single object
	var report CheckovReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return []CheckovReport{report}, nil
}

// ConvertCheckovToHDF converts checkov output to HDF format.
// Accepts native checkov JSON (single object or array) and SARIF format.
// SARIF input is detected automatically and delegated to the shared SARIF converter.
func ConvertCheckovToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("checkov: empty input")
	}
	if err := shared.ValidateJSONSize(input, "checkov", 0); err != nil {
		return nil, fmt.Errorf("checkov: %w", err)
	}

	// Detect SARIF format and delegate
	if result := registry.DetectConverter(input); result != nil && result.Fingerprint.ID == "sarif-to-hdf" {
		return sarif.ConvertSarifToHDF(input, converterVersion)
	}

	reports, err := parseInput(input)
	if err != nil {
		return nil, fmt.Errorf("checkov: %w", err)
	}

	checksum := shared.InputChecksum(input)

	// Merge all checks from all frameworks
	var allChecks []checkWithType
	var checkTypes []string
	var version string

	for _, report := range reports {
		checkTypes = append(checkTypes, report.CheckType)
		if version == "" && report.Summary.CheckovVersion != "" {
			version = report.Summary.CheckovVersion
		}
		for _, group := range [][]CheckovCheck{report.Results.PassedChecks, report.Results.FailedChecks, report.Results.SkippedChecks} {
			for _, check := range group {
				allChecks = append(allChecks, checkWithType{check: check, checkType: report.CheckType})
			}
		}
	}

	// Checkov native JSON carries no per-finding or scan timestamp; use conversion time
	// for every result's StartTime, the no-findings placeholder, and the doc Timestamp.
	now := time.Now().UTC()

	limitedChecks := shared.LimitSliceWithWarning(allChecks, 0, "check")
	order, groups := groupByCheckID(limitedChecks)
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, checkID := range order {
		requirements[i] = buildRequirement(checkID, groups[checkID], now)
	}

	// The joined check_types survive only in the no-findings message; the
	// per-finding scan scope lives in requirement tags (never tool.format).
	format := strings.Join(checkTypes, ", ")

	if len(requirements) == 0 {
		target := format
		if target == "" {
			target = "input"
		}
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"checkov-no-findings",
				fmt.Sprintf("Checkov scanned %s and reported zero findings.", target),
				now,
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Checkov Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "checkov-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Checkov",
		ToolVersion:      version,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &now,
	}), nil
}
