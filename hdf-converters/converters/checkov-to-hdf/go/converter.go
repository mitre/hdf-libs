package checkov

import (
	"encoding/json"
	"fmt"
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
	return fmt.Sprintf("Resource: %s\nFile: %s (lines %v)",
		check.Resource, check.FilePath, check.FileLineRange)
}

// checkToResult converts a single CheckovCheck into an HDF RequirementResult.
func checkToResult(check CheckovCheck) hdf.RequirementResult {
	status := mapStatus(check.CheckResult.Result)
	codeDesc := formatCodeDesc(check)

	var message *string
	if status == hdf.NotReviewed && check.CheckResult.SuppressComment != "" {
		msg := check.CheckResult.SuppressComment
		message = &msg
	}

	return hdf.RequirementResult{
		Status:   status,
		CodeDesc: codeDesc,
		Message:  message,
	}
}

// groupByCheckID groups checks by check_id, preserving insertion order.
func groupByCheckID(checks []CheckovCheck) ([]string, map[string][]CheckovCheck) {
	order := []string{}
	groups := map[string][]CheckovCheck{}
	for _, check := range checks {
		if _, seen := groups[check.CheckID]; !seen {
			order = append(order, check.CheckID)
		}
		groups[check.CheckID] = append(groups[check.CheckID], check)
	}
	return order, groups
}

// buildRequirement converts a group of checks sharing a check_id into one EvaluatedRequirement.
func buildRequirement(checkID string, checks []CheckovCheck) hdf.EvaluatedRequirement {
	rep := checks[0]

	nist := make([]string, len(shared.DefaultStaticAnalysisNIST))
	copy(nist, shared.DefaultStaticAnalysisNIST)

	tags := map[string]interface{}{
		"nist": nist,
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
		results[i] = checkToResult(check)
	}

	title := rep.CheckName
	return hdf.EvaluatedRequirement{
		ID:                 checkID,
		Title:              &title,
		Impact:             getImpact(rep.Severity),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
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
	var allChecks []CheckovCheck
	var checkTypes []string
	var version string

	for _, report := range reports {
		checkTypes = append(checkTypes, report.CheckType)
		if version == "" && report.Summary.CheckovVersion != "" {
			version = report.Summary.CheckovVersion
		}
		allChecks = append(allChecks, report.Results.PassedChecks...)
		allChecks = append(allChecks, report.Results.FailedChecks...)
		allChecks = append(allChecks, report.Results.SkippedChecks...)
	}

	limitedChecks := shared.LimitSliceWithWarning(allChecks, 0, "check")
	order, groups := groupByCheckID(limitedChecks)
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, checkID := range order {
		requirements[i] = buildRequirement(checkID, groups[checkID])
	}

	// Build tool format from check_types
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
				time.Now().UTC(),
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Checkov Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	now := time.Now().UTC()
	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "checkov-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Checkov",
		ToolVersion:      version,
		ToolFormat:       format,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &now,
	}), nil
}
