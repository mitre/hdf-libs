// Package scoutsuite converts ScoutSuite cloud security audit output to HDF format.
package scoutsuite

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/mitre/hdf-mappings/go/cci"
	"github.com/mitre/hdf-mappings/go/scoutsuite"
	hdf "github.com/mitre/hdf-schema"
)

// ScoutSuiteReport is the top-level ScoutSuite JSON output structure.
type ScoutSuiteReport struct {
	AccountID    string                     `json:"account_id"`
	Environment  string                     `json:"environment"`
	LastRun      LastRun                    `json:"last_run"`
	Partition    string                     `json:"partition"`
	ProviderCode string                     `json:"provider_code"`
	ProviderName string                     `json:"provider_name"`
	Services     map[string]json.RawMessage `json:"services"`
}

// LastRun holds metadata about the ScoutSuite run.
type LastRun struct {
	RulesetAbout string `json:"ruleset_about"`
	RulesetName  string `json:"ruleset_name"`
	Time         string `json:"time"`
	Version      string `json:"version"`
}

// ServiceData holds the findings for a single cloud service.
type ServiceData struct {
	Findings map[string]Finding `json:"findings"`
}

// Finding represents a single ScoutSuite finding/rule result.
type Finding struct {
	CheckedItems int             `json:"checked_items"`
	Compliance   json.RawMessage `json:"compliance"`
	Description  string          `json:"description"`
	FlaggedItems int             `json:"flagged_items"`
	IDSuffix     string          `json:"id_suffix"`
	Items        []string        `json:"items"`
	Level        string          `json:"level"`
	Path         string          `json:"path"`
	Rationale    string          `json:"rationale"`
	References   []string        `json:"references"`
	Remediation  *string         `json:"remediation"`
	Service      string          `json:"service"`
}

// ComplianceItem represents a compliance reference in a finding.
type ComplianceItem struct {
	Name      string `json:"name"`
	Reference string `json:"reference"`
	Version   string `json:"version"`
}

// getImpact maps ScoutSuite level strings to HDF impact values.
func getImpact(level string) float64 {
	switch strings.ToLower(level) {
	case "danger":
		return 0.7
	case "warning":
		return 0.5
	default:
		return 0.3
	}
}

// getStatus determines the HDF result status based on checked and flagged item counts.
func getStatus(checkedItems, flaggedItems int) hdf.ResultStatus {
	if checkedItems == 0 {
		return hdf.NotReviewed
	}
	if flaggedItems == 0 {
		return hdf.Passed
	}
	return hdf.Failed
}

// getMessage builds the result message based on checked/flagged item counts and items list.
func getMessage(checkedItems, flaggedItems int, items []string) string {
	if checkedItems == 0 {
		return "Skipped because no items were checked"
	}
	if flaggedItems == 0 {
		return fmt.Sprintf("0 flagged items out of %d checked items", checkedItems)
	}
	msg := fmt.Sprintf("%d flagged items out of %d checked items", flaggedItems, checkedItems)
	if len(items) > 0 {
		msg += ":\n" + strings.Join(items, "\n")
	}
	return msg
}

// scoutsuiteJSPrefix matches known ScoutSuite JS variable assignment prefixes.
// Only these recognized prefixes are stripped; unrecognized content before '{'
// is preserved so the JSON parser produces a clear error.
var scoutsuiteJSPrefix = regexp.MustCompile(`(?i)^\s*(scoutsuite_results)\s*=\s*$`)

// stripJSPrefix removes the "scoutsuite_results = " JS variable prefix from input.
// ScoutSuite outputs results as a JS file with this prefix on the first line.
// Only strips prefixes matching known ScoutSuite patterns; unrecognized prefixes
// are left intact so JSON parsing produces a descriptive error.
func stripJSPrefix(input string) string {
	idx := strings.Index(input, "{")
	if idx < 0 {
		return input
	}
	if idx == 0 {
		return input // Already valid JSON
	}
	prefix := strings.TrimSpace(input[:idx])
	if scoutsuiteJSPrefix.MatchString(prefix) {
		return input[idx:]
	}
	// Unknown prefix — don't strip, let JSON parser report the error
	return input
}

// collapseFindings extracts all findings from all services into a flat list of (ruleID, finding) pairs.
func collapseFindings(report *ScoutSuiteReport) ([]string, map[string]Finding) {
	findings := make(map[string]Finding)
	var order []string

	// Sort service names for deterministic output
	serviceNames := make([]string, 0, len(report.Services))
	for name := range report.Services {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)

	for _, serviceName := range serviceNames {
		raw := report.Services[serviceName]
		var svc ServiceData
		if err := json.Unmarshal(raw, &svc); err != nil {
			continue
		}
		if svc.Findings == nil {
			continue
		}

		// Sort finding keys for deterministic output
		ruleNames := make([]string, 0, len(svc.Findings))
		for name := range svc.Findings {
			ruleNames = append(ruleNames, name)
		}
		sort.Strings(ruleNames)

		for _, ruleName := range ruleNames {
			finding := svc.Findings[ruleName]
			order = append(order, ruleName)
			findings[ruleName] = finding
		}
	}

	return order, findings
}

// buildRequirement converts a single ScoutSuite finding into an EvaluatedRequirement.
func buildRequirement(ruleID string, finding Finding, startTime string) hdf.EvaluatedRequirement {
	// Look up NIST controls from the ScoutSuite mapping
	nist := scoutsuite.NISTControls(ruleID)
	if nist == nil {
		nist = []string{"SA-11", "RA-5"} // fallback
	}

	cciTags := cci.NISTToCCI(nist)
	tags := shared.BuildNISTCCITags(nist, cciTags)

	// Build descriptions
	descriptions := []hdf.Description{
		{Label: "default", Data: finding.Rationale},
	}
	if finding.Remediation != nil && *finding.Remediation != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  *finding.Remediation,
		})
	}

	// Determine status and message
	status := getStatus(finding.CheckedItems, finding.FlaggedItems)
	message := getMessage(finding.CheckedItems, finding.FlaggedItems, finding.Items)

	// Parse start time
	parsedTime := shared.ParseTimestamp(startTime)
	if parsedTime.IsZero() {
		// Try ScoutSuite-specific format: "2021-02-19 19:16:10+0000"
		t, err := time.Parse("2006-01-02 15:04:05-0700", startTime)
		if err == nil {
			parsedTime = t
		}
	}

	result := hdf.RequirementResult{
		Status:   status,
		CodeDesc: finding.Description,
		Message:  &message,
	}

	if !parsedTime.IsZero() {
		result.StartTime = parsedTime
	}

	title := finding.Description
	return hdf.EvaluatedRequirement{
		ID:           ruleID,
		Title:        &title,
		Impact:       getImpact(finding.Level),
		Tags:         tags,
		Descriptions: descriptions,
		Results:      []hdf.RequirementResult{result},
	}
}

// ConvertScoutsuiteToHDF converts ScoutSuite output to HDF format.
// Input may be a JS file with "scoutsuite_results = " prefix or pure JSON.
func ConvertScoutsuiteToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("scoutsuite: empty input")
	}
	if err := shared.ValidateJSONSize(input, "scoutsuite", 0); err != nil {
		return nil, fmt.Errorf("scoutsuite: %w", err)
	}

	// Strip JS variable prefix if present
	jsonStr := stripJSPrefix(string(input))

	checksum := shared.InputChecksum([]byte(jsonStr))

	var report ScoutSuiteReport
	if err := json.Unmarshal([]byte(jsonStr), &report); err != nil {
		return nil, fmt.Errorf("scoutsuite: invalid JSON: %w", err)
	}

	// Collapse all service findings into a flat list
	order, findings := collapseFindings(&report)

	order = shared.LimitSliceWithWarning(order, 0, "finding")

	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, ruleID := range order {
		requirements[i] = buildRequirement(ruleID, findings[ruleID], report.LastRun.Time)
	}

	title := fmt.Sprintf("Scout Suite Report using %s ruleset on %s with account %s",
		report.LastRun.RulesetName, report.ProviderName, report.AccountID)

	baseline := hdf.EvaluatedBaseline{
		Name:            "ScoutSuite Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}
	baseline.Title = &title

	if report.LastRun.RulesetAbout != "" {
		baseline.Summary = &report.LastRun.RulesetAbout
	}

	// Target name: "{ruleset_name} ruleset:{provider_name}:{account_id}"
	targetName := fmt.Sprintf("%s ruleset:%s:%s",
		report.LastRun.RulesetName, report.ProviderName, report.AccountID)

	// Parse timestamp
	var timestamp *time.Time
	parsedTime := shared.ParseTimestamp(report.LastRun.Time)
	if parsedTime.IsZero() {
		// Try ScoutSuite format: "2021-02-19 19:16:10+0000"
		t, err := time.Parse("2006-01-02 15:04:05-0700", report.LastRun.Time)
		if err == nil {
			parsedTime = t
		}
	}
	if !parsedTime.IsZero() {
		timestamp = &parsedTime
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:     "scoutsuite-to-hdf",
		ConverterVersion:  converterVersion,
		ToolName:          "ScoutSuite",
		ToolFormat:        "JSON",
		ToolVersion:       report.LastRun.Version,
		Baselines:         []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{
				Name: targetName,
				Type: hdf.CloudAccount,
				Labels: map[string]string{
					"account":  report.AccountID,
					"provider": report.ProviderCode,
				},
			},
		},
		Timestamp: timestamp,
	}), nil
}
