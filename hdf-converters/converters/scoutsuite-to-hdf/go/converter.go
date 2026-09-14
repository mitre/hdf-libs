// Package scoutsuite converts ScoutSuite cloud security audit output to HDF format.
package scoutsuite

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/scoutsuite"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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

// complianceStrings renders a finding's compliance references as readable
// "<name> <reference> (v<version>)" strings, preserving source order. Returns
// nil when the compliance array is empty, absent, or unparseable.
func complianceStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var items []ComplianceItem
	if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, c := range items {
		out = append(out, fmt.Sprintf("%s %s (v%s)", c.Name, c.Reference, c.Version))
	}
	return out
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

// serviceFinding pairs a finding with the service that reported it. Carrying the
// service alongside the rule key is what keeps two services reporting the same
// key distinct: keying findings by rule alone let the second service's finding
// overwrite the first while both still emitted a requirement, so one finding was
// lost and the other appeared twice.
type serviceFinding struct {
	service string
	ruleID  string
	finding Finding
}

// collapseFindings flattens every service's findings into one ordered list,
// services then rule keys sorted for deterministic output. Each entry stands
// alone, so no finding can be overwritten by another service's.
func collapseFindings(report *ScoutSuiteReport) []serviceFinding {
	var found []serviceFinding

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
			found = append(found, serviceFinding{
				service: serviceName,
				ruleID:  ruleName,
				finding: svc.Findings[ruleName],
			})
		}
	}

	return found
}

// assignRequirementIDs returns the HDF requirement ID for each finding. A rule
// key is the ID on its own, which is what every ScoutSuite report produces: a
// key names one rule file, whose path binds it to a single service. Should a key
// arrive under two services anyway, both are qualified with their service so the
// IDs stay unique — qualifying only on collision keeps ordinary output unchanged
// rather than renaming every requirement for a case that does not occur.
func assignRequirementIDs(found []serviceFinding) []string {
	occurrences := make(map[string]int, len(found))
	for _, sf := range found {
		occurrences[sf.ruleID]++
	}

	ids := make([]string, len(found))
	for i, sf := range found {
		ids[i] = sf.ruleID
		if occurrences[sf.ruleID] > 1 {
			ids[i] = sf.service + ":" + sf.ruleID
		}
	}
	return ids
}

// buildRequirement converts a single ScoutSuite finding into an EvaluatedRequirement.
// buildRequirement converts a single ScoutSuite finding into an EvaluatedRequirement.
// id is the emitted requirement ID, which may be service-qualified; ruleID is
// always the bare rule key, since that is what the NIST mapping is keyed on.
func buildRequirement(id, ruleID string, finding Finding, startTime string) hdf.EvaluatedRequirement {
	// Look up NIST controls from the ScoutSuite mapping
	nist := scoutsuite.NISTControls(ruleID)
	if nist == nil {
		nist = []string{"SA-11", "RA-5"} // fallback
	}

	cciTags := cci.NISTToCCI(nist)
	tags := shared.BuildNISTCCITags(nist, cciTags)

	// Carry compliance framework references (CIS benchmark, etc.) into tags.
	if compliance := complianceStrings(finding.Compliance); len(compliance) > 0 {
		tags["compliance"] = compliance
	}

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

	// Build external references (ScoutSuite carries a list of URL strings)
	var hdfRefs []hdf.Reference
	for _, ref := range finding.References {
		if ref == "" {
			continue
		}
		urlCopy := ref
		hdfRefs = append(hdfRefs, hdf.Reference{URL: &urlCopy})
	}

	// Determine status and message
	status := getStatus(finding.CheckedItems, finding.FlaggedItems)
	message := getMessage(finding.CheckedItems, finding.FlaggedItems, finding.Items)

	// Parse start time
	parsedTime := hdfutil.ParseTimestamp(startTime)
	if parsedTime.IsZero() {
		// Try ScoutSuite-specific format: "2021-02-19 19:16:10+0000"
		t, err := time.Parse("2006-01-02 15:04:05-0700", startTime)
		if err == nil {
			parsedTime = hdfutil.NormalizeTimestamp(t)
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
	req := hdf.EvaluatedRequirement{
		ID:                 id,
		Title:              &title,
		Impact:             getImpact(finding.Level),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Refs:               hdfRefs,
		Results:            []hdf.RequirementResult{result},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}

	// Promote the finding's cloud-resource locus into the structured, queryable
	// sourceLocation. ScoutSuite paths (e.g. "cloudtrail.regions.id.trails.id")
	// carry no line number, so Line is omitted.
	if finding.Path != "" {
		req.SourceLocation = &hdf.SourceLocation{Ref: hdfutil.Ptr(finding.Path)}
	}

	return req
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
	found := collapseFindings(&report)

	found = shared.LimitSliceWithWarning(found, 0, "finding")
	ids := assignRequirementIDs(found)

	requirements := make([]hdf.EvaluatedRequirement, len(found))
	for i, sf := range found {
		requirements[i] = buildRequirement(ids[i], sf.ruleID, sf.finding, report.LastRun.Time)
	}

	targetName := fmt.Sprintf("%s ruleset:%s:%s",
		report.LastRun.RulesetName, report.ProviderName, report.AccountID)

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"scoutsuite-no-findings",
				fmt.Sprintf("ScoutSuite scanned %s and reported zero findings.", targetName),
				time.Now().UTC(),
			),
		}
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

	// Parse timestamp
	var timestamp *time.Time
	parsedTime := hdfutil.ParseTimestamp(report.LastRun.Time)
	if parsedTime.IsZero() {
		// Try ScoutSuite format: "2021-02-19 19:16:10+0000"
		t, err := time.Parse("2006-01-02 15:04:05-0700", report.LastRun.Time)
		if err == nil {
			parsedTime = hdfutil.NormalizeTimestamp(t)
		}
	}
	if !parsedTime.IsZero() {
		timestamp = &parsedTime
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "scoutsuite-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "ScoutSuite",
		ToolVersion:      report.LastRun.Version,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
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
