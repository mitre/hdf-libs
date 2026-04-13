package snyk

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sarif "github.com/mitre/hdf-converters/converters/sarif-to-hdf/go"
	"github.com/mitre/hdf-converters/registry"
	shared "github.com/mitre/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
	"github.com/mitre/hdf-mappings/go/cci"
	hdf "github.com/mitre/hdf-schema"
)

// SnykReport is the top-level Snyk test JSON output structure.
type SnykReport struct {
	OK              bool       `json:"ok"`
	Vulnerabilities []SnykVuln `json:"vulnerabilities"`
	DependencyCount int        `json:"dependencyCount"`
	Org             string     `json:"org"`
	PackageManager  string     `json:"packageManager"`
	Summary         string     `json:"summary"`
	ProjectName     string     `json:"projectName"`
	Path            string     `json:"path"`
}

// SnykVuln represents a single vulnerability entry from Snyk output.
type SnykVuln struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    string          `json:"severity"`
	CvssScore   float64         `json:"cvssScore"`
	CVSSv3      string          `json:"CVSSv3"`
	Identifiers SnykIdentifiers `json:"identifiers"`
	Language    string          `json:"language"`
	PackageName string          `json:"packageName"`
	ModuleName  string          `json:"moduleName"`
	Version     string          `json:"version"`
	From        []string        `json:"from"`
	UpgradePath []interface{}   `json:"upgradePath"`
	FixedIn     []string        `json:"fixedIn"`
	Exploit     string          `json:"exploit"`
}

// SnykIdentifiers holds the CVE, CWE, and GHSA identifiers for a vulnerability.
type SnykIdentifiers struct {
	CVE  []string `json:"CVE"`
	CWE  []string `json:"CWE"`
	GHSA []string `json:"GHSA"`
}

// getImpact maps Snyk severity strings to HDF impact values.
func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpact(severity, 0.5)
}

// formatDependencyPath formats the "from" array as a human-readable dependency path.
func formatDependencyPath(from []string) string {
	if len(from) == 0 {
		return "Unknown dependency path"
	}
	return fmt.Sprintf("From: [ %s ]", strings.Join(from, ", "))
}

// groupByID groups vulnerabilities by ID, preserving insertion order.
func groupByID(vulns []SnykVuln) ([]string, map[string][]SnykVuln) {
	order := []string{}
	groups := map[string][]SnykVuln{}
	for _, vuln := range vulns {
		if _, seen := groups[vuln.ID]; !seen {
			order = append(order, vuln.ID)
		}
		groups[vuln.ID] = append(groups[vuln.ID], vuln)
	}
	return order, groups
}

// buildRequirement converts a group of vulnerabilities sharing an ID into one
// EvaluatedRequirement with multiple results.
func buildRequirement(vulnID string, vulns []SnykVuln) hdf.EvaluatedRequirement {
	rep := vulns[0]

	nist := shared.MapCWEToNIST(rep.Identifiers.CWE, shared.DefaultStaticAnalysisNIST)
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{}
	if len(rep.Identifiers.CWE) > 0 {
		extras["cweid"] = rep.Identifiers.CWE
	}
	if len(rep.Identifiers.CVE) > 0 {
		extras["cveid"] = rep.Identifiers.CVE
	}
	if len(rep.Identifiers.GHSA) > 0 {
		extras["ghsaid"] = rep.Identifiers.GHSA
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	descriptions := []hdf.Description{
		{Label: "default", Data: rep.Description},
	}

	results := make([]hdf.RequirementResult, len(vulns))
	for i, vuln := range vulns {
		results[i] = hdf.RequirementResult{
			Status:   hdf.Failed,
			CodeDesc: formatDependencyPath(vuln.From),
		}
	}

	title := rep.Title
	return hdf.EvaluatedRequirement{
		ID:           vulnID,
		Title:        &title,
		Impact:       getImpact(rep.Severity),
		Tags:         tags,
		Descriptions: descriptions,
		Results:      results,
	}
}

// convertSingleProject converts a single Snyk project report to an HDF baseline.
func convertSingleProject(report SnykReport, checksum *hdf.Checksum) hdf.EvaluatedBaseline {
	limitedVulns := shared.LimitSliceWithWarning(report.Vulnerabilities, 0, "vulnerability")
	order, groups := groupByID(limitedVulns)
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, vulnID := range order {
		requirements[i] = buildRequirement(vulnID, groups[vulnID])
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Snyk Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	title := fmt.Sprintf("Snyk Project: %s Snyk Path: %s", report.ProjectName, report.Path)
	baseline.Title = &title

	if report.Summary != "" {
		baseline.Summary = &report.Summary
	}

	return baseline
}

// ConvertSnykToHDF converts Snyk output to HDF format.
// Accepts both native Snyk JSON and SARIF format — SARIF input is detected
// automatically and delegated to the shared SARIF converter.
// Handles both single-project (object) and multi-project (array) input.
func ConvertSnykToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("snyk: empty input")
	}
	if err := shared.ValidateJSONSize(input, "snyk", 0); err != nil {
		return nil, fmt.Errorf("snyk: %w", err)
	}

	// Detect format: if SARIF, delegate to the shared SARIF converter
	if result := registry.DetectConverter(input); result != nil && result.Fingerprint.ID == "sarif-to-hdf" {
		return sarif.ConvertSarifToHDF(input, converterVersion)
	}

	checksum := shared.InputChecksum(input)

	// Try single project first
	var report SnykReport
	if err := json.Unmarshal(input, &report); err != nil {
		// Try array of projects
		var reports []SnykReport
		if arrErr := json.Unmarshal(input, &reports); arrErr != nil {
			return nil, fmt.Errorf("snyk: invalid JSON: %w", err)
		}
		return convertMultiProject(reports, checksum, converterVersion)
	}

	// Validate structure — must have vulnerabilities field
	// (json.Unmarshal succeeds on any JSON; check for expected content)
	if report.Vulnerabilities == nil {
		// Re-check: maybe it was actually an array
		var reports []SnykReport
		if arrErr := json.Unmarshal(input, &reports); arrErr == nil && len(reports) > 0 {
			return convertMultiProject(reports, checksum, converterVersion)
		}
		// Default to empty vulnerabilities — Snyk output for clean projects
		// has "vulnerabilities": [] which parses as nil slice vs null
	}

	baseline := convertSingleProject(report, checksum)

	targetName := report.ProjectName
	if targetName == "" {
		targetName = report.Path
	}

	now := time.Now().UTC()

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "snyk-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Snyk",
		ToolFormat:       "JSON",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{Name: targetName, Type: hdf.CopyrightApplication},
		},
		Timestamp: &now,
	}), nil
}

func convertMultiProject(reports []SnykReport, checksum *hdf.Checksum, converterVersion string) (*hdf.HDFResults, error) {
	limitedReports := shared.LimitSliceWithWarning(reports, 0, "project")
	baselines := make([]hdf.EvaluatedBaseline, len(limitedReports))
	for i, report := range limitedReports {
		baselines[i] = convertSingleProject(report, checksum)
	}

	now := time.Now().UTC()

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "snyk-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Snyk",
		ToolFormat:       "JSON",
		Baselines:        baselines,
		Timestamp:        &now,
	}), nil
}
