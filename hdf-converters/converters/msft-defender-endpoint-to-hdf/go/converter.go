package msftdefenderendpoint

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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

// An MDE alert is a detection that fired, so every alert is a raw Failed result.
// Consumer triage (falsePositive, expected-activity) never flips the raw status —
// it rides in a structured Status_Override that carries effectiveStatus + full
// provenance (see buildTriageOverride). The raw failure and the attributed,
// expiring override are both present.
const rawAlertStatus = hdf.Failed

// triageIdentity resolves the alert's human triager (assignedTo) to an HDF
// Identity, typed as email when the value looks like an address. When no owner is
// recorded, falls back to an honest system identity rather than inventing a person.
func triageIdentity(assignedTo *string) hdf.Identity {
	if assignedTo != nil && *assignedTo != "" {
		if strings.Contains(*assignedTo, "@") {
			return hdf.Identity{Type: hdf.Email, Identifier: *assignedTo}
		}
		return hdf.Identity{Type: hdf.Username, Identifier: *assignedTo}
	}
	return hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: "Microsoft Defender for Endpoint (automated triage)"}
}

// triageReason renders the override justification from the alert's determination
// and classification (e.g. "notMalicious (falsePositive)").
func triageReason(alert mdeAlert) string {
	class := ""
	if alert.Classification != nil {
		class = *alert.Classification
	}
	det := ""
	if alert.Determination != nil {
		det = *alert.Determination
	}
	switch {
	case det != "" && class != "":
		return fmt.Sprintf("%s (%s)", det, class)
	case det != "":
		return det
	case class != "":
		return class
	default:
		return "Triaged in Microsoft Defender for Endpoint"
	}
}

// buildTriageOverride turns an MDE alert's classification triage into a structured
// HDF Status_Override with full provenance (assignedTo owner, resolvedDateTime
// applied time). Returns ok=false when the classification carries no
// override-worthy decision (truePositive or untriaged → raw stays failed).
//   - falsePositive → falsePositive override, effectiveStatus notApplicable (the
//     detection was wrong, so the finding does not apply; disposition distinguishes
//     it from a genuine N/A).
//   - informationalExpectedActivity → waiver override, effectiveStatus passed (the
//     activity is real but expected/authorized, i.e. an accepted risk).
func buildTriageOverride(alert mdeAlert, startTime time.Time) (hdf.StatusOverride, hdf.ResultStatus, hdf.OverrideType, bool) {
	if alert.Classification == nil {
		return hdf.StatusOverride{}, "", "", false
	}
	var oType hdf.OverrideType
	var effective hdf.ResultStatus
	switch strings.ToLower(*alert.Classification) {
	case "falsepositive":
		oType = hdf.FalsePositive
		effective = hdf.NotApplicable
	case "informationalexpectedactivity":
		oType = hdf.OverrideTypeWaiver
		effective = hdf.Passed
	default: // truePositive, unknownFutureValue, … → no override
		return hdf.StatusOverride{}, "", "", false
	}

	appliedAt := time.Time{}
	if alert.ResolvedDateTime != nil {
		appliedAt = hdfutil.ParseTimestamp(*alert.ResolvedDateTime)
	}
	if appliedAt.IsZero() {
		appliedAt = hdfutil.ParseTimestamp(alert.LastUpdateDateTime)
	}
	if appliedAt.IsZero() {
		appliedAt = startTime
	}

	status := effective
	override := hdf.StatusOverride{
		Type:      oType,
		Status:    &status,
		Reason:    triageReason(alert),
		AppliedBy: triageIdentity(alert.AssignedTo),
		AppliedAt: appliedAt,
		ExpiresAt: appliedAt.AddDate(1, 0, 0),
	}
	return override, effective, oType, true
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

// extractDeviceTarget extracts a Host target from device evidence if present,
// carrying the MDE device id (externalIds.mde) plus rbac/health/onboarding labels.
// Falls back to tenantId as a cloud account target when no device evidence exists.
func extractDeviceTarget(alert mdeAlert) hdf.Component {
	for _, ev := range alert.Evidence {
		odataType, _ := ev["@odata.type"].(string)
		if !strings.Contains(odataType, "deviceEvidence") {
			continue
		}
		deviceName, _ := ev["deviceDnsName"].(string)
		mdeDeviceID, _ := ev["mdeDeviceId"].(string)
		// A device with neither a name nor an id carries no usable identity.
		if deviceName == "" && mdeDeviceID == "" {
			continue
		}
		osPlatform, _ := ev["osPlatform"].(string)

		name := deviceName
		if name == "" {
			name = mdeDeviceID
		}
		labels := map[string]string{"provider": "azure"}
		if rbac, _ := ev["rbacGroupName"].(string); rbac != "" {
			labels["rbacGroupName"] = rbac
		}
		if health, _ := ev["healthStatus"].(string); health != "" {
			labels["healthStatus"] = health
		}
		if onboarding, _ := ev["onboardingStatus"].(string); onboarding != "" {
			labels["onboardingStatus"] = onboarding
		}
		target := hdf.Component{
			Name:   name,
			Type:   hdf.Host,
			Labels: labels,
		}
		if deviceName != "" {
			target.FQDN = hdfutil.Ptr(deviceName)
		}
		if osPlatform != "" {
			target.OSName = hdfutil.Ptr(osPlatform)
		}
		if mdeDeviceID != "" {
			target.ExternalIDS = map[string]string{"mde": mdeDeviceID}
		}
		return target
	}
	// No device evidence — use tenant as cloud account
	return hdf.Component{
		Name:      alert.TenantID,
		Type:      hdf.CloudAccount,
		AccountID: hdfutil.Ptr(alert.TenantID),
		Labels:    map[string]string{"account": alert.TenantID, "provider": "azure"},
	}
}

// targetDedupKey returns the identity used to deduplicate scan-target components:
// the MDE device id when present, else the component name.
func targetDedupKey(target hdf.Component) string {
	if id, ok := target.ExternalIDS["mde"]; ok && id != "" {
		return "mde:" + id
	}
	return target.Name
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

	if alert.IncidentID != "" {
		// Emit as a number when the id is a canonical base-10 integer (round-trips
		// cleanly); otherwise preserve the source string verbatim. The round-trip
		// guard keeps Go/TS byte-parity for edge cases like leading zeros.
		if n, err := strconv.ParseInt(alert.IncidentID, 10, 64); err == nil && strconv.FormatInt(n, 10) == alert.IncidentID {
			tags["incident_id"] = n
		} else {
			tags["incident_id"] = alert.IncidentID
		}
	}
	if alert.DetectionSource != "" {
		tags["detection_source"] = alert.DetectionSource
	}
	if alert.ServiceSource != "" {
		tags["service_source"] = alert.ServiceSource
	}
	if alert.ThreatFamilyName != nil && *alert.ThreatFamilyName != "" {
		tags["threat_family_name"] = *alert.ThreatFamilyName
	}

	return tags
}

// deriveScanTimestamp returns the latest source alert time as the top-level
// report timestamp: the freshest lastUpdateDateTime across alerts, falling back
// per alert to lastActivityDateTime then createdDateTime. Source-derived so the
// conversion is deterministic. Returns the zero time when no alert carries a
// parseable time (caller falls back to the conversion time).
func deriveScanTimestamp(alerts []mdeAlert) time.Time {
	var latest time.Time
	for _, alert := range alerts {
		t := hdfutil.ParseTimestamp(alert.LastUpdateDateTime)
		if t.IsZero() {
			t = hdfutil.ParseTimestamp(alert.LastActivityDateTime)
		}
		if t.IsZero() {
			t = hdfutil.ParseTimestamp(alert.CreatedDateTime)
		}
		if t.IsZero() {
			continue
		}
		if t.After(latest) {
			latest = t
		}
	}
	return latest
}

// alertToRequirement converts a single MDE alert into an HDF EvaluatedRequirement.
func alertToRequirement(alert mdeAlert, scanTime time.Time) hdf.EvaluatedRequirement {
	impact := severityToImpact(alert.Severity)

	codeDesc := formatEvidence(alert.Evidence)
	msg := formatMessage(alert)

	startTime := hdfutil.ParseTimestamp(alert.FirstActivityDateTime)
	if startTime.IsZero() {
		startTime = hdfutil.ParseTimestamp(alert.CreatedDateTime)
	}
	if startTime.IsZero() {
		startTime = scanTime
	}

	result := hdf.RequirementResult{
		Status:    rawAlertStatus,
		CodeDesc:  codeDesc,
		Message:   &msg,
		StartTime: startTime,
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

	var refs []hdf.Reference
	if alert.AlertWebURL != "" {
		url := alert.AlertWebURL
		refs = []hdf.Reference{{URL: &url}}
	}

	tags := buildTags(alert)

	title := alert.Title
	req := hdf.EvaluatedRequirement{
		ID:                 alert.ID,
		Title:              &title,
		Impact:             impact,
		Tags:               tags,
		Descriptions:       descriptions,
		Refs:               refs,
		Results:            []hdf.RequirementResult{result},
		ControlType:        shared.DeriveControlTypeFromTags(shared.DefaultStaticAnalysisNIST),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}

	// Consumer triage becomes a structured override (raw failure + attributed,
	// expiring override both present). When the classification carries no
	// override-worthy decision (truePositive / untriaged), preserve the raw
	// classification + determination as loose tags instead.
	if override, effective, oType, ok := buildTriageOverride(alert, startTime); ok {
		req.StatusOverrides = []hdf.StatusOverride{override}
		req.EffectiveStatus = &effective
		req.Disposition = &oType
	} else {
		if alert.Classification != nil && *alert.Classification != "" {
			tags["classification"] = *alert.Classification
		}
		if alert.Determination != nil && *alert.Determination != "" {
			tags["determination"] = *alert.Determination
		}
	}

	return req
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

	scanTime := time.Now().UTC()

	limitedAlerts := shared.LimitSliceWithWarning(response.Value, 0, "alert")

	// Top-level timestamp is source-derived (latest alert time), not now(), so the
	// conversion is deterministic. Fall back to the conversion time only when the
	// input carries no parseable alert time (e.g. an empty tenant window).
	timestamp := deriveScanTimestamp(limitedAlerts)
	if timestamp.IsZero() {
		timestamp = scanTime
	}

	requirements := make([]hdf.EvaluatedRequirement, len(limitedAlerts))
	for i, alert := range limitedAlerts {
		requirements[i] = alertToRequirement(alert, scanTime)
	}

	seenTargets := make(map[string]bool)
	var targets []hdf.Component
	for _, alert := range limitedAlerts {
		target := extractDeviceTarget(alert)
		key := targetDedupKey(target)
		if !seenTargets[key] {
			seenTargets[key] = true
			targets = append(targets, target)
		}
	}

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"msft-defender-endpoint-no-findings",
				"Microsoft Defender for Endpoint scanned the tenant and reported zero findings.",
				scanTime,
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Microsoft Defender for Endpoint Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "msft-defender-endpoint-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Microsoft Defender for Endpoint",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       targets,
		Timestamp:        &timestamp,
	}), nil
}
