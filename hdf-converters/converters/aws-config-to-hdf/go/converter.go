// Package awsconfig converts AWS Config compliance evaluation results to HDF format.
package awsconfig

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	awsconfigmap "github.com/mitre/hdf-libs/hdf-mappings/go/v3/awsconfig"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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

	resultsChecksum := shared.InputChecksum(input)

	var data ConfigRulesFile
	if err := json.Unmarshal(input, &data); err != nil {
		return nil, fmt.Errorf("failed to parse AWS Config JSON: %w", err)
	}
	if data.ConfigRules == nil {
		return nil, fmt.Errorf("invalid AWS Config export: ConfigRules field is required")
	}

	limitedRules := shared.LimitSliceWithWarning(data.ConfigRules, 0, "rule")

	if err := checkRevisionAlignment(limitedRules); err != nil {
		return nil, err
	}

	baseline := buildBaseline(limitedRules, resultsChecksum)
	now := time.Now().UTC()

	// Extract account/region from first rule's ARN for target labels
	firstArn := ""
	if len(limitedRules) > 0 {
		firstArn = limitedRules[0].ConfigRuleArn
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

// buildBaseline creates one EvaluatedBaseline from the (already size-limited) ConfigRules.
func buildBaseline(rules []ConfigRule, resultsChecksum *hdf.Checksum) hdf.EvaluatedBaseline {
	requirements := make([]hdf.EvaluatedRequirement, 0, len(rules))
	for _, rule := range rules {
		requirements = append(requirements, buildRequirement(rule))
	}

	return hdf.EvaluatedBaseline{
		Name:            "AWS Config",
		Title:           hdfutil.Ptr("AWS Config Compliance Results"),
		Version:         hdfutil.Ptr("1.0.0"),
		Maintainer:      hdfutil.Ptr("Amazon Web Services"),
		ResultsChecksum: resultsChecksum,
		Requirements:    requirements,
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
	if len(reqResults) == 0 {
		// Issue #80 bug 2: a Config rule that was deployed and active but
		// evaluated zero in-scope resources (e.g. rds-cluster-multi-az-enabled
		// in an account with no RDS clusters) returns an empty
		// EvaluationResults from GetComplianceDetailsByConfigRule. The HDF
		// schema requires Results.minItems >= 1, so synthesize one
		// notApplicable result honestly signaling that the rule had no scope.
		reqResults = append(reqResults, buildNotApplicableResult(rule))
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
		ControlType:  shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
		SourceLocation: &hdf.SourceLocation{
			Ref:  &arnRef,
			Line: &line,
		},
		Results:            reqResults,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// buildNotApplicableResult synthesizes a single HDF result for a Config rule
// whose live evaluation returned zero in-scope resources. The HDF schema
// requires Results.minItems >= 1; emitting this synthesized result honestly
// signals to auditors that the rule's check ran but had no scope in this
// account/region rather than vacuously claiming "passed". See issue #80 bug 2.
func buildNotApplicableResult(rule ConfigRule) hdf.RequirementResult {
	return hdf.RequirementResult{
		Status:    hdf.NotApplicable,
		CodeDesc:  fmt.Sprintf("AWS Config rule %s evaluated zero in-scope resources in this account/region.", rule.ConfigRuleName),
		StartTime: time.Now().UTC(),
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

// checkRevisionAlignment flags rules whose NIST mappings exist at a revision
// other than the one currently selected. Such rules emit no NIST tags at the
// selected revision even though a mapping exists elsewhere — a likely sign the
// wrong --nist-rev was chosen for the input. Rules unmapped at every revision
// are not flagged; they are a coverage gap, not a revision mismatch. In strict
// mode this is a hard error; otherwise it logs a single aggregated warning.
func checkRevisionAlignment(rules []ConfigRule) error {
	rev := nist.Revision()
	seen := make(map[string]bool)
	var lines []string
	for _, rule := range rules {
		covered := awsconfigmap.MappedRevisions(rule.Source.SourceIdentifier, rule.ConfigRuleName)
		if len(covered) == 0 || containsInt(covered, rev) || seen[rule.ConfigRuleName] {
			continue
		}
		seen[rule.ConfigRuleName] = true
		lines = append(lines, fmt.Sprintf("  - %s (mapped at Rev %s)", rule.ConfigRuleName, joinInts(covered)))
	}
	if len(lines) == 0 {
		return nil
	}

	detail := fmt.Sprintf("%d AWS Config rule(s) have NIST 800-53 mappings at a different revision than the requested Rev %d; their NIST tags were omitted:\n%s",
		len(lines), rev, strings.Join(lines, "\n"))
	if nist.Strict() {
		return fmt.Errorf("aws-config: %s\nre-run with a matching --nist-rev, or drop --nist-strict to convert with the gaps", detail)
	}
	log.Printf("WARNING: %s", detail)
	return nil
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func joinInts(s []int) string {
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

// buildNISTTags looks up NIST controls for the rule, preferring SourceIdentifier.
func buildNISTTags(sourceIdentifier, ruleName string) []string {
	if sourceIdentifier != "" {
		if tags := awsconfigmap.NISTControlsByIdentifier(sourceIdentifier); len(tags) > 0 {
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
