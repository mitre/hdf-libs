package twistlock

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// TwistlockReport is the top-level Twistlock scan output structure.
// Container image scans wrap results in a "results" array; code repo
// scans omit that wrapper and return a single result object directly.
type TwistlockReport struct {
	Results    []TwistlockResult `json:"results"`
	ConsoleURL string            `json:"consoleURL"`
}

// TwistlockResult represents a single scan result (one image or repository).
type TwistlockResult struct {
	ID                        string                 `json:"id"`
	Name                      string                 `json:"name"`
	Repository                string                 `json:"repository"`
	Distro                    string                 `json:"distro"`
	Collections               []string               `json:"collections"`
	Vulnerabilities           []TwistlockVuln        `json:"vulnerabilities"`
	VulnerabilityDistribution *TwistlockDistribution `json:"vulnerabilityDistribution"`
	ComplianceDistribution    *TwistlockDistribution `json:"complianceDistribution"`
}

// TwistlockVuln represents a single vulnerability entry.
type TwistlockVuln struct {
	ID               string   `json:"id"`
	Status           string   `json:"status"`
	CVSS             float64  `json:"cvss"`
	Vector           string   `json:"vector"`
	Description      string   `json:"description"`
	Severity         string   `json:"severity"`
	PackageName      string   `json:"packageName"`
	PackageVersion   string   `json:"packageVersion"`
	Link             string   `json:"link"`
	RiskFactors      []string `json:"riskFactors"`
	ImpactedVersions []string `json:"impactedVersions"`
	PublishedDate    string   `json:"publishedDate"`
	DiscoveredDate   string   `json:"discoveredDate"`
	FixDate          string   `json:"fixDate"`
	LayerTime        string   `json:"layerTime"`
}

// TwistlockDistribution holds vulnerability/compliance counts by severity.
type TwistlockDistribution struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// getImpact maps Twistlock severity strings to HDF impact values.
// Includes "important" (alias for critical) and "moderate" (alias for medium)
// which appear in some Twistlock outputs. Maps critical to 0.9 (not standard 1.0).

var twistlockAliases = map[string]float64{
	"critical":  0.9,
	"important": 0.9,
	"moderate":  0.5,
}

func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, twistlockAliases, 0.5)
}

// buildTitle constructs the baseline title from scan result data.
// Uses collections (joined with " / ") if present, otherwise falls back
// to the repository field.
func buildTitle(result TwistlockResult) string {
	var projectName string
	switch {
	case result.Repository != "":
		projectName = result.Repository
	case len(result.Collections) > 0:
		projectName = strings.Join(result.Collections, " / ")
	default:
		projectName = "N/A"
	}
	return fmt.Sprintf("Twistlock Project: %s", projectName)
}

// buildSummary constructs the baseline summary from distribution data.
func buildSummary(result TwistlockResult) string {
	vulnTotal := "N/A"
	if result.VulnerabilityDistribution != nil {
		vulnTotal = fmt.Sprintf("%d", result.VulnerabilityDistribution.Total)
	}
	complianceTotal := "N/A"
	if result.ComplianceDistribution != nil {
		complianceTotal = fmt.Sprintf("%d", result.ComplianceDistribution.Total)
	}
	return fmt.Sprintf("Package Vulnerability Summary: %s Application Compliance Issue Total: %s",
		vulnTotal, complianceTotal)
}

// formatCodeDesc builds the code_desc string for a vulnerability result.
func formatCodeDesc(vuln TwistlockVuln) string {
	packageName := vuln.PackageName
	if packageName == "" {
		packageName = "N/A"
	}
	impactedVersions := "N/A"
	if len(vuln.ImpactedVersions) > 0 {
		impactedVersions = fmt.Sprintf("%v", vuln.ImpactedVersions)
	}
	return fmt.Sprintf("Package %q should be updated to latest version above impacted versions %s",
		packageName, impactedVersions)
}

// buildRequirement converts a single vulnerability into an EvaluatedRequirement.
func buildRequirement(vuln TwistlockVuln) hdf.EvaluatedRequirement {
	nist := shared.DefaultRemediationNIST
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{
		"cveid": []interface{}{vuln.ID},
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	descriptions := []hdf.Description{
		{Label: "default", Data: vuln.Description},
	}

	startTime := hdfutil.ParseTimestamp(vuln.DiscoveredDate)

	results := []hdf.RequirementResult{
		{
			Status:    hdf.Failed,
			CodeDesc:  formatCodeDesc(vuln),
			StartTime: startTime,
		},
	}

	title := vuln.ID
	return hdf.EvaluatedRequirement{
		ID:                 vuln.ID,
		Title:              &title,
		Impact:             getImpact(vuln.Severity),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// convertSingleResult converts one TwistlockResult to an EvaluatedBaseline.
func convertSingleResult(result TwistlockResult, checksum *hdf.Checksum) hdf.EvaluatedBaseline {
	vulns := result.Vulnerabilities
	if vulns == nil {
		vulns = []TwistlockVuln{}
	}

	limitedVulns := shared.LimitSliceWithWarning(vulns, 0, "vulnerability")

	requirements := make([]hdf.EvaluatedRequirement, len(limitedVulns))
	for i, vuln := range limitedVulns {
		requirements[i] = buildRequirement(vuln)
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Twistlock Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	title := buildTitle(result)
	baseline.Title = &title

	summary := buildSummary(result)
	baseline.Summary = &summary

	return baseline
}

// ConvertTwistlockToHDF converts Twistlock/Prisma Cloud scan output to HDF format.
// Handles both container image scans (with "results" wrapper) and code repository
// scans (single result object without wrapper).
func ConvertTwistlockToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("twistlock: empty input")
	}
	if err := shared.ValidateJSONSize(input, "twistlock", 0); err != nil {
		return nil, fmt.Errorf("twistlock: %w", err)
	}

	checksum := shared.InputChecksum(input)

	// Try parsing as wrapped report (has "results" key)
	var report TwistlockReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("twistlock: invalid JSON: %w", err)
	}

	// If no results array found, this might be a code repo scan (unwrapped single result)
	if report.Results == nil {
		var singleResult TwistlockResult
		if err := json.Unmarshal(input, &singleResult); err != nil {
			return nil, fmt.Errorf("twistlock: invalid JSON: %w", err)
		}
		report.Results = []TwistlockResult{singleResult}
	}

	if len(report.Results) == 0 {
		return nil, fmt.Errorf("twistlock: no scan results found")
	}

	baselines := make([]hdf.EvaluatedBaseline, len(report.Results))
	for i, result := range report.Results {
		baselines[i] = convertSingleResult(result, checksum)
	}

	// Use the first result's name or repository as target name
	targetName := report.Results[0].Name
	if targetName == "" {
		targetName = report.Results[0].Repository
	}

	now := time.Now().UTC()

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "twistlock-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Twistlock",
		ToolFormat:       "JSON",
		Baselines:        baselines,
		Components: []hdf.Component{
			{
				Name:   targetName,
				Type:   hdf.ContainerImage,
				Labels: map[string]string{"image": report.Results[0].ID},
			},
		},
		Timestamp: &now,
	}), nil
}
