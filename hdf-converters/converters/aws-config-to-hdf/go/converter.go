// Package awsconfig converts AWS Config compliance evaluation results to HDF format.
package awsconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	awsconfigmap "github.com/mitre/hdf-mappings/go/awsconfig"
	hdf "github.com/mitre/hdf-schema"
)

// ---- Input types --------------------------------------------------------

// ConfigRulesFile is the top-level structure of the AWS Config static export.
// It bundles each ConfigRule with its EvaluationResults.
type ConfigRulesFile struct {
	ConfigRules []ConfigRule `json:"ConfigRules"`
}

// ConfigRule represents an AWS Config rule and its compliance evaluation results.
type ConfigRule struct {
	ConfigRuleID      string             `json:"ConfigRuleId"`
	ConfigRuleName    string             `json:"ConfigRuleName"`
	ConfigRuleArn     string             `json:"ConfigRuleArn"`
	Description       string             `json:"Description"`
	Source            ConfigRuleSource   `json:"Source"`
	InputParameters   string             `json:"InputParameters"`
	EvaluationResults []EvaluationResult `json:"EvaluationResults"`
}

// ConfigRuleSource identifies who owns the rule and how to look up its NIST mappings.
type ConfigRuleSource struct {
	Owner            string `json:"Owner"`
	SourceIdentifier string `json:"SourceIdentifier"`
}

// EvaluationResult is one compliance evaluation for a specific resource.
type EvaluationResult struct {
	EvaluationResultIdentifier EvaluationResultIdentifier `json:"EvaluationResultIdentifier"`
	ComplianceType             string                     `json:"ComplianceType"`
	Annotation                 string                     `json:"Annotation"`
	ConfigRuleInvokedTime      string                     `json:"ConfigRuleInvokedTime"` // ISO 8601
	ResultRecordedTime         string                     `json:"ResultRecordedTime"`    // ISO 8601
}

// EvaluationResultIdentifier contains the rule and resource qualifiers.
type EvaluationResultIdentifier struct {
	EvaluationResultQualifier EvaluationResultQualifier `json:"EvaluationResultQualifier"`
}

// EvaluationResultQualifier identifies which rule and resource was evaluated.
type EvaluationResultQualifier struct {
	ConfigRuleName string `json:"ConfigRuleName"`
	ResourceType   string `json:"ResourceType"`
	ResourceID     string `json:"ResourceId"`
}

// ---- Converter ----------------------------------------------------------

var accountIDRe = regexp.MustCompile(`:(\d{12}):config-rule`)

// ConvertAWSConfigToHDF converts a ConfigRulesFile JSON export to HDF format.
func ConvertAWSConfigToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	hash := sha256.Sum256(input)
	checksum := &hdf.Checksum{
		Algorithm: hdf.Sha256,
		Value:     hex.EncodeToString(hash[:]),
	}

	var data ConfigRulesFile
	if err := json.Unmarshal(input, &data); err != nil {
		return nil, fmt.Errorf("failed to parse AWS Config JSON: %w", err)
	}
	if data.ConfigRules == nil {
		return nil, fmt.Errorf("invalid AWS Config export: ConfigRules field is required")
	}

	baseline := buildBaseline(data.ConfigRules, checksum)
	now := time.Now().UTC()

	toolName := "AWS Config"
	return &hdf.HDFResults{
		Generator: &hdf.Generator{
			Name:    "aws-config-to-hdf",
			Version: converterVersion,
		},
		DataSource: &hdf.DataSource{Name: &toolName},
		Baselines:  []hdf.EvaluatedBaseline{baseline},
		Targets:    []hdf.Target{},
		Timestamp:  &now,
	}, nil
}

// buildBaseline creates one EvaluatedBaseline from all ConfigRules.
func buildBaseline(rules []ConfigRule, checksum *hdf.Checksum) hdf.EvaluatedBaseline {
	requirements := make([]hdf.EvaluatedRequirement, 0, len(rules))
	for _, rule := range rules {
		requirements = append(requirements, buildRequirement(rule))
	}

	return hdf.EvaluatedBaseline{
		Name:         "AWS Config",
		Title:        ptr("AWS Config Compliance Results"),
		Version:      ptr("1.0.0"),
		Maintainer:   ptr("Amazon Web Services"),
		Checksum:     checksum,
		Requirements: requirements,
	}
}

// buildRequirement creates one HDF requirement for a single AWS Config rule.
func buildRequirement(rule ConfigRule) hdf.EvaluatedRequirement {
	nistControls := buildNISTTags(rule.Source.SourceIdentifier, rule.ConfigRuleName)
	tags := map[string]interface{}{}
	if len(nistControls) > 0 {
		tags["nist"] = nistControls
	}

	reqResults := make([]hdf.RequirementResult, 0, len(rule.EvaluationResults))
	for _, r := range rule.EvaluationResults {
		reqResults = append(reqResults, buildResult(r))
	}

	line := float64(1)
	arnRef := rule.ConfigRuleArn

	descriptions := []hdf.Description{
		{Label: "default", Data: rule.Description},
		{Label: "check", Data: buildCheckText(rule)},
	}

	return hdf.EvaluatedRequirement{
		ID:           rule.ConfigRuleID,
		Title:        ptr(buildTitle(rule)),
		Descriptions: descriptions,
		Impact: 0.5,
		Tags:   tags,
		SourceLocation: &hdf.SourceLocation{
			Ref:  &arnRef,
			Line: &line,
		},
		Results: reqResults,
	}
}

// buildResult creates one HDF RequirementResult from a single EvaluationResult.
func buildResult(r EvaluationResult) hdf.RequirementResult {
	q := r.EvaluationResultIdentifier.EvaluationResultQualifier
	status := mapComplianceStatus(r.ComplianceType)
	codeDesc := buildCodeDesc(q)
	startTime := parseISO(r.ConfigRuleInvokedTime)
	runTime := computeRunTime(r.ConfigRuleInvokedTime, r.ResultRecordedTime)

	return hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc,
		StartTime: startTime,
		RunTime:   runTime,
		Message:   buildMessage(codeDesc, r.Annotation, status),
	}
}

// mapComplianceStatus maps AWS Config ComplianceType values to HDF ResultStatus.
func mapComplianceStatus(compliance string) hdf.ResultStatus {
	switch compliance {
	case "COMPLIANT":
		return hdf.Passed
	case "NON_COMPLIANT":
		return hdf.Failed
	case "NOT_APPLICABLE":
		return hdf.NotApplicable
	default: // INSUFFICIENT_DATA and unknown values
		return hdf.NotReviewed
	}
}

// buildNISTTags looks up NIST controls for the rule, preferring SourceIdentifier.
func buildNISTTags(sourceIdentifier, ruleName string) []string {
	if sourceIdentifier != "" {
		if tags := awsconfigmap.NISTControls(sourceIdentifier); len(tags) > 0 {
			return tags
		}
	}
	return awsconfigmap.NISTControls(ruleName)
}

// buildTitle formats the control title as "{accountId} - {ruleName}".
func buildTitle(rule ConfigRule) string {
	accountID := getAccountID(rule.ConfigRuleArn)
	return fmt.Sprintf("%s - %s", accountID, rule.ConfigRuleName)
}

// getAccountID extracts the 12-digit AWS account ID from a config-rule ARN.
func getAccountID(arn string) string {
	m := accountIDRe.FindStringSubmatch(arn)
	if len(m) < 2 {
		return "no-account-id"
	}
	return m[1]
}

// buildCheckText creates the "check" description content with ARN, source identifier, and params.
func buildCheckText(rule ConfigRule) string {
	parts := []string{
		fmt.Sprintf("ARN: %s", strOrNA(rule.ConfigRuleArn)),
		fmt.Sprintf("Source Identifier: %s", strOrNA(rule.Source.SourceIdentifier)),
	}
	if rule.InputParameters != "" && rule.InputParameters != "{}" {
		params := strings.ReplaceAll(rule.InputParameters, "{", "")
		params = strings.ReplaceAll(params, "}", "")
		params = strings.ReplaceAll(params, "\"", "")
		for _, p := range strings.Split(params, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				parts = append(parts, p)
			}
		}
	}
	return strings.Join(parts, "<br/>")
}

// buildCodeDesc formats the code description for a result.
func buildCodeDesc(q EvaluationResultQualifier) string {
	return fmt.Sprintf("config_rule_name: %s, resource_type: %s, resource_id: %s",
		q.ConfigRuleName, q.ResourceType, q.ResourceID)
}

// buildMessage returns a failure message or nil for non-failed results.
func buildMessage(codeDesc, annotation string, status hdf.ResultStatus) *string {
	if status != hdf.Failed {
		return nil
	}
	text := annotation
	if text == "" {
		text = "Rule does not pass rule compliance"
	}
	msg := fmt.Sprintf("(%s): %s", codeDesc, text)
	return &msg
}

// parseISO parses an ISO 8601 / RFC3339 timestamp string to time.Time.
func parseISO(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}
		}
	}
	return t
}

// computeRunTime calculates elapsed seconds between two ISO timestamps.
func computeRunTime(invokedStr, recordedStr string) *float64 {
	invoked := parseISO(invokedStr)
	recorded := parseISO(recordedStr)
	if invoked.IsZero() || recorded.IsZero() {
		return nil
	}
	secs := recorded.Sub(invoked).Seconds()
	return &secs
}

// strOrNA returns the string if non-empty, otherwise "N/A".
func strOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T { return &v }
