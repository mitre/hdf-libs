// Package awsconfig converts AWS Config compliance evaluation results to HDF format.
package awsconfig

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	awsconfigmap "github.com/mitre/hdf-libs/hdf-mappings/go/awsconfig"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
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

var arnRe = regexp.MustCompile(`arn:aws[^:]*:config:([^:]+):(\d{12}):config-rule`)

// ConvertAWSConfigToHDF converts a ConfigRulesFile JSON export to HDF format.
func ConvertAWSConfigToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if err := shared.ValidateJSONSize(input, "aws-config", 0); err != nil {
		return nil, fmt.Errorf("aws-config: %w", err)
	}

	integrity := shared.InputIntegrity(input)

	var data ConfigRulesFile
	if err := json.Unmarshal(input, &data); err != nil {
		return nil, fmt.Errorf("failed to parse AWS Config JSON: %w", err)
	}
	if data.ConfigRules == nil {
		return nil, fmt.Errorf("invalid AWS Config export: ConfigRules field is required")
	}

	baseline := buildBaseline(data.ConfigRules, integrity)
	now := time.Now().UTC()

	// Extract account/region from first rule's ARN for target labels
	firstArn := ""
	if len(data.ConfigRules) > 0 {
		firstArn = data.ConfigRules[0].ConfigRuleArn
	}
	accountID := getAccountID(firstArn)
	region := getRegion(firstArn)

	target := hdf.Component{
		Name: fmt.Sprintf("AWS Account %s", accountID),
		Type: hdf.CloudAccount,
		Labels: map[string]string{
			"account":  accountID,
			"region":   region,
			"provider": "aws",
		},
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "aws-config-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "AWS Config",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       []hdf.Component{target},
		Timestamp:        &now,
	}), nil
}

// buildBaseline creates one EvaluatedBaseline from all ConfigRules.
func buildBaseline(rules []ConfigRule, integrity *hdf.Integrity) hdf.EvaluatedBaseline {
	limitedRules := shared.LimitSliceWithWarning(rules, 0, "rule")
	requirements := make([]hdf.EvaluatedRequirement, 0, len(limitedRules))
	for _, rule := range limitedRules {
		requirements = append(requirements, buildRequirement(rule))
	}

	return hdf.EvaluatedBaseline{
		Name:         "AWS Config",
		Title:        hdfutil.Ptr("AWS Config Compliance Results"),
		Version:      hdfutil.Ptr("1.0.0"),
		Maintainer:   hdfutil.Ptr("Amazon Web Services"),
		Integrity:    integrity,
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
		Title:        hdfutil.Ptr(buildTitle(rule)),
		Descriptions: descriptions,
		Impact:       0.5,
		Tags:         tags,
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
	startTime := hdfutil.ParseTimestamp(r.ConfigRuleInvokedTime)
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
	m := arnRe.FindStringSubmatch(arn)
	if len(m) < 3 {
		return "no-account-id"
	}
	return m[2]
}

// getRegion extracts the AWS region from a config-rule ARN.
func getRegion(arn string) string {
	m := arnRe.FindStringSubmatch(arn)
	if len(m) < 2 {
		return "unknown"
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

// computeRunTime calculates elapsed seconds between two ISO timestamps.
func computeRunTime(invokedStr, recordedStr string) *float64 {
	invoked := hdfutil.ParseTimestamp(invokedStr)
	recorded := hdfutil.ParseTimestamp(recordedStr)
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
