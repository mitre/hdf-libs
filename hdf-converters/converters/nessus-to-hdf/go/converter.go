package nessus

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	nessusmappings "github.com/mitre/hdf-libs/hdf-mappings/go/v3/nessus"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// nessusAliases maps Nessus numeric severity levels and CAT compliance categories
// to HDF impact values. Canonical reference: heimdall2 nessus-mapper.ts.
var nessusAliases = map[string]float64{
	"4":   0.9, // Critical
	"3":   0.7, // High
	"i":   0.7, // CAT I
	"2":   0.5, // Medium
	"ii":  0.5, // CAT II
	"1":   0.3, // Low
	"iii": 0.3, // CAT III
	"0":   0.0, // Info
}

// ConvertNessusToHDF converts Nessus XML scan results to HDF format
func ConvertNessusToHDF(nessusXML []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(nessusXML) == 0 {
		return nil, fmt.Errorf("nessus: empty input")
	}
	if err := shared.ValidateXMLInput(nessusXML, 0); err != nil {
		return nil, fmt.Errorf("nessus: %w", err)
	}

	// Calculate checksum of source scan data for integrity verification
	resultsChecksum := shared.InputChecksum(nessusXML)

	var nessus NessusXML
	if err := xml.Unmarshal(nessusXML, &nessus); err != nil {
		return nil, fmt.Errorf("failed to parse Nessus XML: %w", err)
	}

	policyName := nessus.Policy.PolicyName
	version := extractVersion(&nessus)
	reportHosts := nessus.Report.ReportHosts

	limitedHosts := shared.LimitSliceWithWarning(reportHosts, 0, "host")

	// Calculate timing from first and last host
	startTime, duration := calculateTiming(limitedHosts)

	var baselines []hdf.EvaluatedBaseline
	var targets []hdf.Component

	// Process each ReportHost
	for _, host := range limitedHosts {
		baseline := convertReportHostToBaseline(&host, policyName, version, resultsChecksum)
		baselines = append(baselines, baseline)

		target := convertReportHostToTarget(&host)
		targets = append(targets, target)
	}

	result := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "nessus-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Nessus",
		Baselines:        baselines,
		Components:       targets,
		Statistics: &hdf.Statistics{
			Duration: &duration,
		},
		Timestamp: &startTime,
	})

	return result, nil
}

func extractVersion(nessus *NessusXML) string {
	prefs := nessus.Policy.Preferences.ServerPreferences.Preference
	for _, pref := range prefs {
		if pref.Name == "sc_version" {
			return pref.Value
		}
	}
	return ""
}

func calculateTiming(hosts []ReportHost) (time.Time, float64) {
	if len(hosts) == 0 {
		return time.Now(), 0
	}

	firstHost := hosts[0]
	lastHost := hosts[len(hosts)-1]

	startTimeStr := getHostPropertyValue(&firstHost, "HOST_START")
	endTimeStr := getHostPropertyValue(&lastHost, "HOST_END")
	if endTimeStr == "" {
		endTimeStr = getHostPropertyValue(&lastHost, "HOST_START")
	}

	startTime := parseHostTime(startTimeStr)
	endTime := parseHostTime(endTimeStr)

	duration := endTime.Sub(startTime).Seconds()
	if duration < 0 {
		duration = 0
	}

	return startTime, duration
}

func parseHostTime(timeStr string) time.Time {
	t := hdfutil.ParseTimestamp(timeStr)
	if t.IsZero() {
		return time.Now()
	}
	return t
}

func getHostPropertyValue(host *ReportHost, name string) string {
	for _, tag := range host.HostProperties.Tags {
		if tag.Name == name {
			return tag.Value
		}
	}
	return ""
}

func convertReportHostToBaseline(host *ReportHost, policyName, version string, resultsChecksum *hdf.Checksum) hdf.EvaluatedBaseline {
	var requirements []hdf.EvaluatedRequirement

	limitedItems := shared.LimitSliceWithWarning(host.ReportItems, 0, "report item")
	for _, item := range limitedItems {
		req := convertReportItemToRequirement(&item, host)
		requirements = append(requirements, req)
	}

	name := fmt.Sprintf("Nessus %s", policyName)
	title := fmt.Sprintf("Nessus %s", policyName)
	status := "loaded"
	summary := fmt.Sprintf("Nessus %s", policyName)

	return hdf.EvaluatedBaseline{
		Name:            name,
		Title:           &title,
		Version:         &version,
		Status:          &status,
		Summary:         &summary,
		ResultsChecksum: resultsChecksum,
		Requirements:    requirements,
	}
}

func convertReportItemToRequirement(item *ReportItem, host *ReportHost) hdf.EvaluatedRequirement {
	isCompliance := item.ComplianceReference != ""

	// Determine ID
	id := item.PluginID
	if isCompliance {
		vulnIDs := parseComplianceRef(item.ComplianceReference, "Vuln-ID")
		if len(vulnIDs) > 0 && vulnIDs[0] != "" {
			id = vulnIDs[0]
		}
	}

	// Determine title
	title := item.PluginName
	if isCompliance && item.ComplianceCheckName != "" {
		title = item.ComplianceCheckName
	}

	descriptions := buildDescriptions(item, isCompliance)
	impact := calculateImpact(item, isCompliance)
	tags := buildTags(item, isCompliance)
	refs := buildRefs(item)
	results := []hdf.RequirementResult{buildResult(item, host, isCompliance)}

	// Serialize item as code
	codeBytes, _ := json.MarshalIndent(item, "", "  ")
	code := string(codeBytes)

	return hdf.EvaluatedRequirement{
		ID:                 id,
		Title:              &title,
		Descriptions:       descriptions,
		Impact:             impact,
		Tags:               tags,
		Refs:               refs,
		Results:            results,
		Code:               &code,
		ControlType:        shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
		VerificationMethod: shared.DeriveVerificationMethod(&code),
	}
}

func buildDescriptions(item *ReportItem, isCompliance bool) []hdf.Description {
	var descriptions []hdf.Description

	// Default description
	if isCompliance && item.ComplianceInfo != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  parseHTML(item.ComplianceInfo),
		})
	} else {
		// Non-compliance: create description from metadata
		parts := []string{
			fmt.Sprintf("Plugin Family: %s", item.PluginFamily),
			fmt.Sprintf("Port: %s", item.Port),
			fmt.Sprintf("Protocol: %s", item.Protocol),
		}
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  strings.Join(parts, "; ") + ";",
		})
	}

	// Fix/solution description
	solution := item.Solution
	if isCompliance {
		solution = item.ComplianceSolution
	}

	if solution != "" {
		if solution == "n/a" {
			descriptions = append(descriptions, hdf.Description{
				Label: "fix",
				Data:  "n/a",
			})
		} else {
			descriptions = append(descriptions, hdf.Description{
				Label: "fix",
				Data:  parseHTML(solution),
			})
		}
	}

	return descriptions
}

func calculateImpact(item *ReportItem, isCompliance bool) float64 {
	if isCompliance && item.ComplianceReference != "" {
		cats := parseComplianceRef(item.ComplianceReference, "CAT")
		if len(cats) > 0 {
			cat := strings.ToLower(cats[0])
			return hdfutil.SeverityToImpactWithAliases(cat, nessusAliases, 0.5)
		}
		return 0.5 // Default for compliance
	}

	return hdfutil.SeverityToImpactWithAliases(item.Severity, nessusAliases, 0.0)
}

func buildTags(item *ReportItem, isCompliance bool) map[string]interface{} {
	tags := make(map[string]interface{})

	// RID tag
	if isCompliance {
		ruleIDs := parseComplianceRef(item.ComplianceReference, "Rule-ID")
		tags["rid"] = strings.Join(ruleIDs, ",")
	} else {
		tags["rid"] = item.PluginID
	}

	// NIST tags
	if isCompliance && item.ComplianceReference != "" {
		cciTags := parseComplianceRef(item.ComplianceReference, "CCI")
		tags["cci"] = cciTags
		tags["nist"] = cci.CCIToNIST(cciTags)
	} else {
		nist := nessusmappings.NISTControls(item.PluginFamily, item.PluginID)
		if nist == nil {
			nist = []string{}
		}
		tags["nist"] = nist
	}

	// STIG ID for compliance
	if isCompliance && item.ComplianceReference != "" {
		stigID := strings.Join(parseComplianceRef(item.ComplianceReference, "STIG-ID"), ",")
		if stigID != "" {
			tags["stig_id"] = stigID
		}
	}

	// Additional Nessus metadata tags
	if item.RiskFactor != "" {
		tags["risk_factor"] = item.RiskFactor
	}
	if item.PluginType != "" {
		tags["plugin_type"] = item.PluginType
	}
	if item.PluginPublicationDate != "" {
		tags["plugin_publication_date"] = item.PluginPublicationDate
	}
	if item.FName != "" {
		tags["fname"] = item.FName
	}
	if item.CVSS3BaseScore != "" {
		tags["cvss3_base_score"] = item.CVSS3BaseScore
	}
	if item.CVSSBaseScore != "" {
		tags["cvss_base_score"] = item.CVSSBaseScore
	}

	return tags
}

func buildRefs(item *ReportItem) []hdf.Reference {
	var refs []hdf.Reference

	if item.SeeAlso != "" {
		url := item.SeeAlso
		refs = append(refs, hdf.Reference{
			URL: &url,
		})
	}

	return refs
}

func buildResult(item *ReportItem, host *ReportHost, isCompliance bool) hdf.RequirementResult {
	status := getStatus(item, isCompliance)
	codeDesc := getCodeDesc(item)

	message := item.PluginOutput
	if isCompliance && item.ComplianceActualValue != "" {
		message = item.ComplianceActualValue
	}

	startTimeStr := getHostPropertyValue(host, "HOST_START")
	startTime := parseHostTime(startTimeStr)

	result := hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc,
		StartTime: startTime,
	}

	if message != "" {
		result.Message = &message
	}

	return result
}

func getStatus(item *ReportItem, isCompliance bool) hdf.ResultStatus {
	if isCompliance && item.ComplianceResult != "" {
		switch item.ComplianceResult {
		case "PASSED":
			return hdf.Passed
		case "WARNING":
			return hdf.NotApplicable // Heimdall2 maps WARNING to skipped
		case "ERROR":
			return hdf.Error
		default:
			return hdf.Failed
		}
	}

	// Non-compliance items are always failed (informational findings)
	return hdf.Failed
}

func getCodeDesc(item *ReportItem) string {
	desc := item.Description
	if desc == "" {
		desc = item.PluginOutput
	}
	if desc == "" {
		desc = "This Nessus Plugin does not provide output message."
	}
	return parseHTML(desc)
}

func parseComplianceRef(ref, key string) []string {
	var results []string
	elements := strings.Split(ref, ",")

	for _, element := range elements {
		if strings.HasPrefix(element, key) {
			parts := strings.Split(element, "|")
			if len(parts) > 1 {
				results = append(results, parts[1])
			} else {
				results = append(results, "")
			}
		}
	}

	return results
}

func parseHTML(html string) string {
	return hdfutil.StripHTML(html)
}

func convertReportHostToTarget(host *ReportHost) hdf.Component {
	hostName := host.Name

	// Extract host properties
	var fqdn, ipAddress, osName, osVersion *string

	// Determine FQDN: if the hostname is an FQDN, populate the fqdn field
	if isFQDN(hostName) {
		fqdn = &hostName
	}

	// Determine IP address: prefer host-ip property, fall back to name if it's an IP
	if hostIP := getHostPropertyValue(host, "host-ip"); hostIP != "" {
		ipAddress = &hostIP
	} else if isIPAddress(hostName) {
		ipAddress = &hostName
	}

	// Extract operating system information
	if osInfo := getHostPropertyValue(host, "operating-system"); osInfo != "" {
		osName = &osInfo
	}

	// Extract OS version if available
	if osVer := getHostPropertyValue(host, "os"); osVer != "" {
		osVersion = &osVer
	}

	return hdf.Component{
		Name:      hostName,
		Type:      hdf.Host,
		FQDN:      fqdn,
		IPAddress: ipAddress,
		OSName:    osName,
		OSVersion: osVersion,
	}
}

func isFQDN(s string) bool {
	// Must contain at least one dot
	if !strings.Contains(s, ".") {
		return false
	}

	// Must not be an IP address
	if isIPAddress(s) {
		return false
	}

	// Should have at least 2 parts (hostname.domain)
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}

	// All parts should be non-empty and valid hostname components
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}
		// Hostname components can't start or end with hyphen
		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
	}

	return true
}

func isIPAddress(s string) bool {
	// Simple check for IPv4 address format
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
