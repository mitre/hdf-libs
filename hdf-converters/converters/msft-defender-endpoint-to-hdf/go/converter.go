package msftdefenderendpoint

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
)

// mdeAlertResponse represents the top-level Microsoft Graph Security API v2 response.
type mdeAlertResponse struct {
	Value []mdeAlert `json:"value"`
}

// mdeAlert represents a single alert from Microsoft Defender for Endpoint.
type mdeAlert struct {
	ID                    string                   `json:"id"`
	IncidentID            string                   `json:"incidentId"`
	Status                string                   `json:"status"`
	Severity              string                   `json:"severity"`
	Classification        *string                  `json:"classification"`
	Determination         *string                  `json:"determination"`
	ServiceSource         string                   `json:"serviceSource"`
	DetectionSource       string                   `json:"detectionSource"`
	Category              string                   `json:"category"`
	Title                 string                   `json:"title"`
	Description           string                   `json:"description"`
	AlertWebURL           string                   `json:"alertWebUrl"`
	CreatedDateTime       string                   `json:"createdDateTime"`
	FirstActivityDateTime string                   `json:"firstActivityDateTime"`
	LastActivityDateTime  string                   `json:"lastActivityDateTime"`
	LastUpdateDateTime    string                   `json:"lastUpdateDateTime"`
	ResolvedDateTime      *string                  `json:"resolvedDateTime"`
	AssignedTo            *string                  `json:"assignedTo"`
	TenantID              string                   `json:"tenantId"`
	ActorDisplayName      *string                  `json:"actorDisplayName"`
	ThreatDisplayName     *string                  `json:"threatDisplayName"`
	ThreatFamilyName      *string                  `json:"threatFamilyName"`
	MitreTechniques       []string                 `json:"mitreTechniques"`
	RecommendedActions    string                   `json:"recommendedActions"`
	Comments              []interface{}            `json:"comments"`
	Evidence              []map[string]interface{} `json:"evidence"`
}

// severityToImpact maps MDE severity strings to HDF impact values.
func severityToImpact(severity string) float64 {
	return hdfutil.SeverityToImpact(severity, 0.5)
}

// statusToResult maps MDE alert status and classification to HDF result status.
// new/inProgress → Failed, resolved with falsePositive → Passed, resolved otherwise → Failed.
func statusToResult(status string, classification *string) hdf.ResultStatus {
	lower := strings.ToLower(status)
	if lower == "resolved" {
		if classification != nil && strings.ToLower(*classification) == "falsepositive" {
			return hdf.Passed
		}
		return hdf.Failed
	}
	return hdf.Failed
}

// formatEvidence builds a human-readable evidence string for the code_desc field.
func formatEvidence(evidence []map[string]interface{}) string {
	if len(evidence) == 0 {
		return "No evidence available"
	}

	var parts []string
	for _, ev := range evidence {
		odataType, _ := ev["@odata.type"].(string)
		switch {
		case strings.Contains(odataType, "deviceEvidence"):
			deviceName, _ := ev["deviceDnsName"].(string)
			osPlatform, _ := ev["osPlatform"].(string)
			parts = append(parts, fmt.Sprintf("Device: %s (OS: %s)", deviceName, osPlatform))
		case strings.Contains(odataType, "processEvidence"):
			cmdLine, _ := ev["processCommandLine"].(string)
			if imageFile, ok := ev["imageFile"].(map[string]interface{}); ok {
				fileName, _ := imageFile["fileName"].(string)
				filePath, _ := imageFile["filePath"].(string)
				parts = append(parts, fmt.Sprintf("Process: %s\\%s (Command: %s)", filePath, fileName, cmdLine))
			} else {
				parts = append(parts, fmt.Sprintf("Process: (Command: %s)", cmdLine))
			}
		case strings.Contains(odataType, "fileEvidence"):
			fileName, _ := ev["fileName"].(string)
			filePath, _ := ev["filePath"].(string)
			parts = append(parts, fmt.Sprintf("File: %s\\%s", filePath, fileName))
		default:
			parts = append(parts, fmt.Sprintf("Evidence type: %s", odataType))
		}
	}

	return strings.Join(parts, "\n")
}

// formatMessage builds the message string for a result.
func formatMessage(alert mdeAlert) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Alert: %s", alert.Title))
	parts = append(parts, fmt.Sprintf("Status: %s", alert.Status))
	parts = append(parts, fmt.Sprintf("Severity: %s", alert.Severity))
	if alert.ThreatDisplayName != nil && *alert.ThreatDisplayName != "" {
		parts = append(parts, fmt.Sprintf("Threat: %s", *alert.ThreatDisplayName))
	}
	if alert.AlertWebURL != "" {
		parts = append(parts, fmt.Sprintf("URL: %s", alert.AlertWebURL))
	}
	return strings.Join(parts, "\n")
}

// extractDeviceTarget extracts a Host target from device evidence if present.
// Falls back to tenantId as a cloud account target.
func extractDeviceTarget(alert mdeAlert) hdf.Component {
	for _, ev := range alert.Evidence {
		odataType, _ := ev["@odata.type"].(string)
		if strings.Contains(odataType, "deviceEvidence") {
			deviceName, _ := ev["deviceDnsName"].(string)
			osPlatform, _ := ev["osPlatform"].(string)
			target := hdf.Component{
				Name:   deviceName,
				Type:   hdf.Host,
				Labels: map[string]string{"provider": "azure"},
			}
			if deviceName != "" {
				target.FQDN = hdfutil.Ptr(deviceName)
			}
			if osPlatform != "" {
				target.OSName = hdfutil.Ptr(osPlatform)
			}
			return target
		}
	}
	// No device evidence — use tenant as cloud account
	return hdf.Component{
		Name:      alert.TenantID,
		Type:      hdf.CloudAccount,
		AccountID: hdfutil.Ptr(alert.TenantID),
		Labels:    map[string]string{"account": alert.TenantID, "provider": "azure"},
	}
}

// buildTags creates the tags map for a requirement.
func buildTags(alert mdeAlert) map[string]interface{} {
	tags := map[string]interface{}{
		"nist": hdfutil.StringsToInterfaces(shared.DefaultStaticAnalysisNIST),
	}

	if alert.Category != "" {
		tags["category"] = alert.Category
	}

	if len(alert.MitreTechniques) > 0 {
		tags["mitre"] = hdfutil.StringsToInterfaces(alert.MitreTechniques)
	}

	if alert.Classification != nil && *alert.Classification != "" {
		tags["classification"] = *alert.Classification
	}
	if alert.Determination != nil && *alert.Determination != "" {
		tags["determination"] = *alert.Determination
	}

	return tags
}

// alertToRequirement converts a single MDE alert into an HDF EvaluatedRequirement.
func alertToRequirement(alert mdeAlert) hdf.EvaluatedRequirement {
	impact := severityToImpact(alert.Severity)
	status := statusToResult(alert.Status, alert.Classification)

	codeDesc := formatEvidence(alert.Evidence)
	msg := formatMessage(alert)

	result := hdf.RequirementResult{
		Status:   status,
		CodeDesc: codeDesc,
		Message:  &msg,
	}

	startTime := hdfutil.ParseTimestamp(alert.FirstActivityDateTime)
	if !startTime.IsZero() {
		result.StartTime = startTime
	}

	descriptions := []hdf.Description{
		{Label: "default", Data: alert.Description},
	}
	if alert.RecommendedActions != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  alert.RecommendedActions,
		})
	}

	title := alert.Title
	return hdf.EvaluatedRequirement{
		ID:           alert.ID,
		Title:        &title,
		Impact:       impact,
		Tags:         buildTags(alert),
		Descriptions: descriptions,
		Results:      []hdf.RequirementResult{result},
	}
}

// ConvertMsftDefenderEndpointToHDF converts Microsoft Defender for Endpoint alerts
// (Microsoft Graph Security API v2 format) to HDF format.
// Each alert becomes one requirement with one result.
func ConvertMsftDefenderEndpointToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("msft-defender-endpoint: empty input")
	}
	if err := shared.ValidateJSONSize(input, "msft-defender-endpoint", 0); err != nil {
		return nil, fmt.Errorf("msft-defender-endpoint: %w", err)
	}

	var response mdeAlertResponse
	if err := json.Unmarshal(input, &response); err != nil {
		return nil, fmt.Errorf("msft-defender-endpoint: invalid JSON: %w", err)
	}

	if response.Value == nil {
		return nil, fmt.Errorf("msft-defender-endpoint: missing or invalid value array")
	}

	checksum := shared.InputChecksum(input)

	limitedAlerts := shared.LimitSliceWithWarning(response.Value, 0, "alert")

	// Build requirements preserving insertion order
	requirements := make([]hdf.EvaluatedRequirement, len(limitedAlerts))
	for i, alert := range limitedAlerts {
		requirements[i] = alertToRequirement(alert)
	}

	// Build targets — deduplicate by device name
	seenTargets := make(map[string]bool)
	var targets []hdf.Component
	for _, alert := range limitedAlerts {
		target := extractDeviceTarget(alert)
		if !seenTargets[target.Name] {
			seenTargets[target.Name] = true
			targets = append(targets, target)
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Microsoft Defender for Endpoint Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	now := time.Now().UTC()
	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "msft-defender-endpoint-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Microsoft Defender for Endpoint",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       targets,
		Timestamp:        &now,
	}), nil
}
