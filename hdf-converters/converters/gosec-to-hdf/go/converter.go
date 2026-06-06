package gosec

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// GosecReport is the top-level gosec JSON output structure.
type GosecReport struct {
	GolangErrors interface{}  `json:"Golang errors"`
	Issues       []GosecIssue `json:"Issues"`
	Stats        GosecStats   `json:"Stats"`
	GosecVersion string       `json:"GosecVersion"`
}

// GosecStats holds scan statistics from gosec output.
type GosecStats struct {
	Files int `json:"files"`
	Lines int `json:"lines"`
	Nosec int `json:"nosec"`
	Found int `json:"found"`
}

// GosecCWE holds the CWE reference attached to each gosec issue.
type GosecCWE struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// GosecSuppression holds a single suppression entry for a gosec issue.
type GosecSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

// GosecIssue represents a single finding from gosec.
type GosecIssue struct {
	Severity     string             `json:"severity"`
	Confidence   string             `json:"confidence"`
	CWE          GosecCWE           `json:"cwe"`
	RuleID       string             `json:"rule_id"`
	Details      string             `json:"details"`
	File         string             `json:"file"`
	Code         string             `json:"code"`
	Line         string             `json:"line"`
	Column       string             `json:"column"`
	Nosec        bool               `json:"nosec"`
	Suppressions []GosecSuppression `json:"suppressions"`
}

// getImpact maps gosec severity strings to HDF impact values.
func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpact(severity, 0.5)
}

// isSuppressed reports whether an issue should be treated as notReviewed.
// An issue is suppressed if nosec is true OR if the suppressions list is non-nil.
func isSuppressed(issue GosecIssue) bool {
	return issue.Nosec || issue.Suppressions != nil
}

// formatSkipMessage builds a human-readable skip message from suppressions.
// Returns nil when suppressions is nil (issue not suppressed).
func formatSkipMessage(suppressions []GosecSuppression) *string {
	if suppressions == nil {
		return nil
	}
	if len(suppressions) == 0 {
		msg := "No justification provided"
		return &msg
	}
	parts := make([]string, len(suppressions))
	for i, s := range suppressions {
		justification := s.Justification
		if justification == "" {
			justification = "No justification provided"
		}
		parts[i] = fmt.Sprintf("%s (%s)", justification, s.Kind)
	}
	msg := strings.Join(parts, "\n")
	return &msg
}

// formatCodeDesc builds the code_desc string for a result.
func formatCodeDesc(issue GosecIssue) string {
	return fmt.Sprintf(
		"Rule %s violation detected at:\nFile: %s\nLine: %s\nColumn: %s",
		issue.RuleID, issue.File, issue.Line, issue.Column,
	)
}

// formatMessage builds the message string for a result.
func formatMessage(issue GosecIssue) string {
	return fmt.Sprintf("%s confidence of rule violation at:\n%s", issue.Confidence, issue.Code)
}

// nistTagsForIssue looks up NIST controls for the issue's CWE, falling back to
// shared.DefaultRemediationNIST when no mapping is found.
func nistTagsForIssue(issue GosecIssue) []string {
	if issue.CWE.ID != "" {
		controls := cwe.NISTControls(issue.CWE.ID)
		if len(controls) > 0 {
			return controls
		}
	}
	return shared.DefaultRemediationNIST
}

// issueToResult converts a single GosecIssue into an HDF RequirementResult.
func issueToResult(issue GosecIssue) hdf.RequirementResult {
	var status hdf.ResultStatus
	var message *string

	if isSuppressed(issue) {
		status = hdf.NotReviewed
		message = formatSkipMessage(issue.Suppressions)
		if message == nil {
			// nosec=true but no suppressions list — report no justification
			msg := "No justification provided"
			message = &msg
		}
	} else {
		status = hdf.Failed
		msg := formatMessage(issue)
		message = &msg
	}

	return hdf.RequirementResult{
		Status:   status,
		CodeDesc: formatCodeDesc(issue),
		Message:  message,
	}
}

// groupByRuleID groups issues by rule_id, preserving insertion order of first
// occurrence so that output is deterministic.
func groupByRuleID(issues []GosecIssue) ([]string, map[string][]GosecIssue) {
	order := []string{}
	groups := map[string][]GosecIssue{}
	for _, issue := range issues {
		if _, seen := groups[issue.RuleID]; !seen {
			order = append(order, issue.RuleID)
		}
		groups[issue.RuleID] = append(groups[issue.RuleID], issue)
	}
	return order, groups
}

// buildRequirement converts a group of issues sharing a rule_id into one
// EvaluatedRequirement with multiple results.
func buildRequirement(ruleID string, issues []GosecIssue) hdf.EvaluatedRequirement {
	// Use the first issue as the representative for rule-level fields.
	rep := issues[0]

	nist := nistTagsForIssue(rep)
	nistIface := make([]string, len(nist))
	copy(nistIface, nist)

	tags := map[string]interface{}{
		"nist": nistIface,
		"cwe": map[string]interface{}{
			"id":  rep.CWE.ID,
			"url": rep.CWE.URL,
		},
	}

	descriptions := []hdf.Description{
		{Label: "default", Data: rep.Details},
		{Label: "check", Data: fmt.Sprintf("CWE-%s: %s", rep.CWE.ID, rep.CWE.URL)},
	}

	results := make([]hdf.RequirementResult, len(issues))
	for i, issue := range issues {
		results[i] = issueToResult(issue)
	}

	title := rep.Details
	return hdf.EvaluatedRequirement{
		ID:                 ruleID,
		Title:              &title,
		Impact:             getImpact(rep.Severity),
		Tags:               tags,
		Descriptions:       descriptions,
		Results:            results,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// ConvertGosecToHDF converts gosec output to HDF format.
// Accepts both native gosec JSON and SARIF format — SARIF input is detected
// automatically and delegated to the shared SARIF converter.
func ConvertGosecToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("gosec: empty input")
	}
	if err := shared.ValidateJSONSize(input, "gosec", 0); err != nil {
		return nil, fmt.Errorf("gosec: %w", err)
	}

	// Detect format: if SARIF, delegate to the shared SARIF converter
	if result := registry.DetectConverter(input); result != nil && result.Fingerprint.ID == "sarif-to-hdf" {
		return sarif.ConvertSarifToHDF(input, converterVersion)
	}

	var report GosecReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("gosec: invalid JSON: %w", err)
	}

	checksum := shared.InputChecksum(input)

	limitedIssues := shared.LimitSliceWithWarning(report.Issues, 0, "issue")
	order, groups := groupByRuleID(limitedIssues)
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, ruleID := range order {
		requirements[i] = buildRequirement(ruleID, groups[ruleID])
	}

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"gosec-no-findings",
				"gosec scanned Go codebase and reported zero findings.",
				time.Now().UTC(),
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "gosec Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	now := time.Now().UTC()
	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "gosec-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "gosec",
		ToolVersion:      report.GosecVersion,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &now,
	}), nil
}
