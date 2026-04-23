package grype_to_hdf

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
)

// Grype JSON report input structures

type GrypeReport struct {
	Descriptor     GrypeDescriptor `json:"descriptor"`
	Source         GrypeSource     `json:"source"`
	Distro         *GrypeDistro    `json:"distro,omitempty"`
	Matches        []GrypeMatch    `json:"matches"`
	IgnoredMatches []GrypeMatch    `json:"ignoredMatches,omitempty"`
}

type GrypeDescriptor struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp,omitempty"`
}

type GrypeSource struct {
	Target struct {
		UserInput string `json:"userInput"`
	} `json:"target"`
}

type GrypeDistro struct {
	Name    string   `json:"name,omitempty"`
	Version string   `json:"version,omitempty"`
	IDLike  []string `json:"idLike,omitempty"`
}

type GrypeMatch struct {
	Vulnerability          GrypeVulnerability          `json:"vulnerability"`
	RelatedVulnerabilities []GrypeRelatedVulnerability `json:"relatedVulnerabilities,omitempty"`
	MatchDetails           []GrypeMatchDetail          `json:"matchDetails"`
	Artifact               GrypeArtifact               `json:"artifact"`
}

type GrypeVulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource,omitempty"`
	Namespace   string      `json:"namespace,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	URLs        []string    `json:"urls,omitempty"`
	Description string      `json:"description,omitempty"`
	CVSS        []GrypeCVSS `json:"cvss,omitempty"`
	Fix         *GrypeFix   `json:"fix,omitempty"`
}

type GrypeRelatedVulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource,omitempty"`
	Namespace   string      `json:"namespace,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	URLs        []string    `json:"urls,omitempty"`
	Description string      `json:"description,omitempty"`
	CVSS        []GrypeCVSS `json:"cvss,omitempty"`
}

type GrypeCVSS struct {
	Version string       `json:"version,omitempty"`
	Vector  string       `json:"vector,omitempty"`
	Metrics *CVSSMetrics `json:"metrics,omitempty"`
}

type CVSSMetrics struct {
	BaseScore           float64 `json:"baseScore,omitempty"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

type GrypeFix struct {
	Versions []string `json:"versions,omitempty"`
	State    string   `json:"state,omitempty"` // "fixed", "unknown", "wontfix", "not-fixed"
}

type GrypeMatchDetail struct {
	Type       string                 `json:"type,omitempty"` // "exact-direct-match", "exact-indirect-match", "cpe-match"
	Matcher    string                 `json:"matcher,omitempty"`
	SearchedBy map[string]interface{} `json:"searchedBy,omitempty"`
	Found      map[string]interface{} `json:"found,omitempty"`
}

type GrypeArtifact struct {
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Type      string          `json:"type,omitempty"` // "apk", "rpm", "deb", "npm", etc.
	Locations []GrypeLocation `json:"locations,omitempty"`
	Licenses  []string        `json:"licenses,omitempty"`
	Language  string          `json:"language,omitempty"`
	CPEs      []string        `json:"cpes,omitempty"`
	PURL      string          `json:"purl,omitempty"`
}

type GrypeLocation struct {
	Path    string `json:"path,omitempty"`
	LayerID string `json:"layerID,omitempty"`
}

// Severity to impact mapping.
// Grype maps "critical" to 0.9 (not the standard 1.0) and adds "negligible"=0.0.

var grypeAliases = map[string]float64{
	"critical":   0.9,
	"negligible": 0.0,
}

func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, grypeAliases, 0.5)
}

func isNegligibleOrUnknown(severity string) bool {
	lower := strings.ToLower(severity)
	return lower == "negligible" || lower == "unknown" || lower == ""
}

func getDescription(vuln GrypeVulnerability, relatedVulns []GrypeRelatedVulnerability) string {
	// Use primary vulnerability description if available
	if vuln.Description != "" {
		return vuln.Description
	}

	// Fall back to related vulnerability with matching ID
	for _, related := range relatedVulns {
		if related.ID == vuln.ID && related.Description != "" {
			return related.Description
		}
	}

	return fmt.Sprintf("Vulnerability %s", vuln.ID)
}

func getFixInfo(fix *GrypeFix) string {
	if fix == nil || fix.State == "" {
		return "vulnerability is not known to be fixed in any versions"
	}

	if fix.State == "fixed" && len(fix.Versions) > 0 {
		return fmt.Sprintf("vulnerability is %s for versions %s", fix.State, strings.Join(fix.Versions, ", "))
	}

	return fmt.Sprintf("vulnerability is %s", fix.State)
}

func getCVSSInfo(vuln GrypeVulnerability, relatedVulns []GrypeRelatedVulnerability) string {
	cvssData := make(map[string]interface{})

	// Collect CVSS from primary vulnerability
	if len(vuln.CVSS) > 0 {
		cvssData["primary"] = vuln.CVSS
	}

	// Collect CVSS from related vulnerabilities
	if len(relatedVulns) > 0 {
		related := []map[string]interface{}{}
		for _, r := range relatedVulns {
			if len(r.CVSS) > 0 {
				related = append(related, map[string]interface{}{
					"id":         r.ID,
					"dataSource": r.DataSource,
					"cvss":       r.CVSS,
				})
			}
		}
		if len(related) > 0 {
			cvssData["related"] = related
		}
	}

	jsonBytes, err := json.Marshal(cvssData)
	if err != nil {
		return "{}"
	}
	return string(jsonBytes)
}

func getReferences(vuln GrypeVulnerability, relatedVulns []GrypeRelatedVulnerability) []string {
	refSet := make(map[string]bool)

	// Add URLs from primary vulnerability
	for _, url := range vuln.URLs {
		refSet[url] = true
	}

	// Add URLs from related vulnerabilities
	for _, related := range relatedVulns {
		for _, url := range related.URLs {
			refSet[url] = true
		}
	}

	// Convert set to slice
	refs := make([]string, 0, len(refSet))
	for url := range refSet {
		refs = append(refs, url)
	}

	return refs
}

func buildCodeDesc(match GrypeMatch) string {
	parts := []string{
		fmt.Sprintf("Package: %s@%s", match.Artifact.Name, match.Artifact.Version),
	}

	// Package type if available
	if match.Artifact.Type != "" {
		parts = append(parts, fmt.Sprintf("Type: %s", match.Artifact.Type))
	}

	// Location if available
	if len(match.Artifact.Locations) > 0 && match.Artifact.Locations[0].Path != "" {
		parts = append(parts, fmt.Sprintf("Location: %s", match.Artifact.Locations[0].Path))
	}

	// Match type if available
	if len(match.MatchDetails) > 0 && match.MatchDetails[0].Type != "" {
		parts = append(parts, fmt.Sprintf("Match Type: %s", match.MatchDetails[0].Type))
	}

	return strings.Join(parts, " | ")
}

func convertMatchToRequirement(match GrypeMatch, isIgnored bool) hdf.EvaluatedRequirement {
	vuln := match.Vulnerability
	cveID := vuln.ID
	severity := vuln.Severity
	impact := getImpact(severity)
	description := getDescription(vuln, match.RelatedVulnerabilities)
	fixInfo := getFixInfo(vuln.Fix)
	cvssInfo := getCVSSInfo(vuln, match.RelatedVulnerabilities)
	refs := getReferences(vuln, match.RelatedVulnerabilities)

	// Determine status
	var status hdf.ResultStatus
	switch {
	case isIgnored:
		status = hdf.NotReviewed // Ignored by configured rules
	case isNegligibleOrUnknown(severity):
		status = hdf.NotApplicable
	default:
		status = hdf.Failed
	}

	// Build result message
	messageParts := []string{}
	if isIgnored {
		messageParts = append(messageParts, "This vulnerability was ignored by configured rules.")
	}
	if isNegligibleOrUnknown(severity) && !isIgnored {
		messageParts = append(messageParts, "Manual review required because a Grype rating severity is set to `negligible` or `unknown`.")
	}
	if severity != "" {
		messageParts = append(messageParts, fmt.Sprintf("Severity: %s", severity))
	} else {
		messageParts = append(messageParts, "Severity: unknown")
	}
	messageParts = append(messageParts, fixInfo)
	message := strings.Join(messageParts, " ")

	// Build execution result
	// Use Go zero time
	zeroTime := time.Time{}

	result := hdf.RequirementResult{
		Status:    status,
		CodeDesc:  buildCodeDesc(match),
		Message:   &message,
		StartTime: zeroTime,
	}

	// Get CCI tags from curated NIST → CCI mapping
	cciTags := cci.NISTToCCI(shared.DefaultStaticAnalysisNIST)

	// Build tags - only include cci if not empty
	tags := shared.BuildNISTCCITags(shared.DefaultStaticAnalysisNIST, cciTags)

	// Build requirement ID
	var requirementID string
	if isIgnored {
		requirementID = fmt.Sprintf("Grype-Ignored-Match/%s", cveID)
	} else {
		requirementID = fmt.Sprintf("Grype/%s", cveID)
	}

	// Build descriptions
	descriptions := []hdf.Description{
		{Label: "default", Data: description},
		{Label: "fix", Data: fixInfo},
		{Label: "check", Data: cvssInfo},
	}

	// Build refs (not a pointer)
	var hdfRefs []hdf.Reference
	if len(refs) > 0 {
		hdfRefs = make([]hdf.Reference, len(refs))
		for i, url := range refs {
			urlCopy := url
			hdfRefs[i] = hdf.Reference{URL: &urlCopy}
		}
	}

	requirement := hdf.EvaluatedRequirement{
		ID:           requirementID,
		Impact:       impact,
		Results:      []hdf.RequirementResult{result},
		Tags:         tags,
		Descriptions: descriptions,
		Refs:         hdfRefs,
	}

	return requirement
}

// ConvertGrypeToHDF converts Grype JSON to HDF
func ConvertGrypeToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("grype: empty input")
	}
	if err := shared.ValidateJSONSize(input, "grype", 0); err != nil {
		return nil, fmt.Errorf("grype: %w", err)
	}

	// Calculate checksum of input data
	resultsChecksum := shared.InputChecksum(input)

	// Parse Grype JSON
	var grypeData GrypeReport
	if err := json.Unmarshal(input, &grypeData); err != nil {
		return nil, fmt.Errorf("invalid Grype JSON: %w", err)
	}

	// Build requirements from matches
	requirements := []hdf.EvaluatedRequirement{}

	// Process regular matches
	limitedMatches := shared.LimitSliceWithWarning(grypeData.Matches, 0, "match")
	for _, match := range limitedMatches {
		requirements = append(requirements, convertMatchToRequirement(match, false))
	}

	// Process ignored matches
	limitedIgnored := shared.LimitSliceWithWarning(grypeData.IgnoredMatches, 0, "ignored match")
	for _, match := range limitedIgnored {
		requirements = append(requirements, convertMatchToRequirement(match, true))
	}

	// Build baseline name from source
	targetName := grypeData.Source.Target.UserInput
	if targetName == "" {
		targetName = "Grype Scan"
	}

	// Create baseline
	baseline := hdf.EvaluatedBaseline{
		Name:            targetName,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	// Build timestamp
	var timestamp *time.Time
	if grypeData.Descriptor.Timestamp != "" {
		parsedTime, err := time.Parse(time.RFC3339Nano, grypeData.Descriptor.Timestamp)
		if err != nil {
			parsedTime, err = time.Parse(time.RFC3339, grypeData.Descriptor.Timestamp)
		}
		if err == nil {
			timestamp = &parsedTime
		}
	}

	// Build target from scan source
	target := hdf.Component{
		Name: targetName,
		Type: hdf.Artifact,
	}

	// Build HDF results
	hdfResult := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "grype-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Grype",
		ToolVersion:      grypeData.Descriptor.Version,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       []hdf.Component{target},
		Timestamp:        timestamp,
	})

	return hdfResult, nil
}
