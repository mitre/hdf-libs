package msftdefendercloud

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// defenderCloudInput is the top-level structure from the Azure Security Assessments REST API.
// Derived from: https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list
type defenderCloudInput struct {
	Value []assessment `json:"value"`
}

// assessment represents a single SecurityAssessmentResponse object.
type assessment struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Type       string               `json:"type"`
	Properties assessmentProperties `json:"properties"`
}

// assessmentProperties holds the core fields of an assessment.
type assessmentProperties struct {
	DisplayName     string          `json:"displayName"`
	ResourceDetails resourceDetails `json:"resourceDetails"`
	Status          statusBlock     `json:"status"`
	Metadata        metadata        `json:"metadata"`
}

// resourceDetails captures the assessed Azure resource.
type resourceDetails struct {
	Source string `json:"source"`
	ID     string `json:"id"`
}

// statusBlock captures the assessment result status.
type statusBlock struct {
	Code        string `json:"code"`
	Cause       string `json:"cause"`
	Description string `json:"description"`
}

// metadata captures the assessment rule metadata.
type metadata struct {
	DisplayName            string   `json:"displayName"`
	AssessmentType         string   `json:"assessmentType"`
	PolicyDefinitionID     string   `json:"policyDefinitionId"`
	Description            string   `json:"description"`
	RemediationDescription string   `json:"remediationDescription"`
	Categories             []string `json:"categories"`
	Severity               string   `json:"severity"`
	UserImpact             string   `json:"userImpact"`
	ImplementationEffort   string   `json:"implementationEffort"`
	Threats                []string `json:"threats"`
	Tactics                []string `json:"tactics"`
	Techniques             []string `json:"techniques"`
}

// mapStatus converts an Azure assessment status code to an HDF ResultStatus.
func mapStatus(code string) hdf.ResultStatus {
	switch strings.ToLower(code) {
	case "healthy":
		return hdf.Passed
	case "unhealthy":
		return hdf.Failed
	case "notapplicable":
		return hdf.NotApplicable
	default:
		return hdf.NotReviewed
	}
}

// extractSubscriptionID extracts the subscription ID from an Azure resource path.
// Example: "/subscriptions/a1b2c3d4-.../resourceGroups/..." → "a1b2c3d4-..."
func extractSubscriptionID(resourcePath string) string {
	lower := strings.ToLower(resourcePath)
	idx := strings.Index(lower, "/subscriptions/")
	if idx == -1 {
		return ""
	}
	rest := resourcePath[idx+len("/subscriptions/"):]
	if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
		return rest[:slashIdx]
	}
	return rest
}

// ConvertMsftDefenderCloudToHDF converts Microsoft Defender for Cloud assessment
// output (Azure REST API format) to HDF format.
func ConvertMsftDefenderCloudToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("msft-defender-cloud: empty input")
	}
	if err := shared.ValidateJSONSize(input, "msft-defender-cloud", 0); err != nil {
		return nil, fmt.Errorf("msft-defender-cloud: %w", err)
	}

	var raw defenderCloudInput
	if err := json.Unmarshal(input, &raw); err != nil {
		return nil, fmt.Errorf("msft-defender-cloud: invalid JSON: %w", err)
	}

	if raw.Value == nil {
		return nil, fmt.Errorf("msft-defender-cloud: missing or invalid value array")
	}

	scanTime := time.Now().UTC()

	checksum := shared.InputChecksum(input)

	limitedAssessments := shared.LimitSliceWithWarning(raw.Value, 0, "assessment")

	// Group assessments by assessment name (GUID), preserving insertion order.
	order := []string{}
	groups := map[string][]assessment{}
	for _, a := range limitedAssessments {
		if _, seen := groups[a.Name]; !seen {
			order = append(order, a.Name)
		}
		groups[a.Name] = append(groups[a.Name], a)
	}

	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, assessmentID := range order {
		requirements[i] = buildRequirement(assessmentID, groups[assessmentID], scanTime)
	}

	subscriptionID := ""
	if len(limitedAssessments) > 0 {
		subscriptionID = extractSubscriptionID(limitedAssessments[0].ID)
	}

	if len(requirements) == 0 {
		targetName := subscriptionID
		if targetName == "" {
			targetName = "Unknown"
		}
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"msft-defender-cloud-no-findings",
				fmt.Sprintf("Microsoft Defender for Cloud scanned %s and reported zero findings.", targetName),
				scanTime,
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Microsoft Defender for Cloud Assessments",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	var targets []hdf.Component
	if subscriptionID != "" {
		azureProvider := hdf.Azure
		targets = []hdf.Component{
			{
				Name:      fmt.Sprintf("Azure Subscription %s", subscriptionID),
				Type:      hdf.CloudAccount,
				AccountID: hdfutil.Ptr(subscriptionID),
				Provider:  &azureProvider,
				Labels: map[string]string{
					"account":  subscriptionID,
					"provider": "azure",
				},
			},
		}
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "msft-defender-cloud-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Microsoft Defender for Cloud",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       targets,
		Timestamp:        &scanTime,
	}), nil
}

// buildRequirement converts a group of assessments sharing an assessment ID
// into one EvaluatedRequirement with one result per assessment.
func buildRequirement(assessmentID string, assessments []assessment, scanTime time.Time) hdf.EvaluatedRequirement {
	rep := assessments[0]
	meta := rep.Properties.Metadata

	impact := hdfutil.SeverityToImpact(meta.Severity, 0.5)

	// Build tags
	tags := map[string]interface{}{}

	// Categories
	if len(meta.Categories) > 0 {
		tags["categories"] = hdfutil.StringsToInterfaces(meta.Categories)
	}

	// MITRE ATT&CK tactics and techniques
	if len(meta.Tactics) > 0 {
		tags["tactics"] = hdfutil.StringsToInterfaces(meta.Tactics)
	}
	if len(meta.Techniques) > 0 {
		tags["techniques"] = hdfutil.StringsToInterfaces(meta.Techniques)
	}

	// Threats
	if len(meta.Threats) > 0 {
		tags["threats"] = hdfutil.StringsToInterfaces(meta.Threats)
	}

	// Severity and additional metadata
	tags["severity"] = meta.Severity
	if meta.UserImpact != "" {
		tags["userImpact"] = meta.UserImpact
	}
	if meta.ImplementationEffort != "" {
		tags["implementationEffort"] = meta.ImplementationEffort
	}
	if meta.AssessmentType != "" {
		tags["assessmentType"] = meta.AssessmentType
	}
	if meta.PolicyDefinitionID != "" {
		tags["policy_definition_id"] = meta.PolicyDefinitionID
	}

	// Descriptions
	descriptions := []hdf.Description{
		{Label: "default", Data: meta.Description},
	}
	if meta.RemediationDescription != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  meta.RemediationDescription,
		})
	}

	// Build results
	results := make([]hdf.RequirementResult, len(assessments))
	for i, a := range assessments {
		results[i] = buildResult(a, scanTime)
	}

	title := rep.Properties.DisplayName
	return hdf.EvaluatedRequirement{
		ID:                 assessmentID,
		Title:              &title,
		Impact:             impact,
		Tags:               tags,
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// buildResult converts a single assessment into an HDF RequirementResult.
func buildResult(a assessment, scanTime time.Time) hdf.RequirementResult {
	status := mapStatus(a.Properties.Status.Code)

	codeDesc := fmt.Sprintf("Resource: %s", a.Properties.ResourceDetails.ID)

	var message *string
	if a.Properties.Status.Description != "" {
		message = hdfutil.Ptr(a.Properties.Status.Description)
	} else if a.Properties.Status.Cause != "" {
		message = hdfutil.Ptr(a.Properties.Status.Cause)
	}

	return hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc,
		Message:   message,
		StartTime: scanTime,
	}
}
