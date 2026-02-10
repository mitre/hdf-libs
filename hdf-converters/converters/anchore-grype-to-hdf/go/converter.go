package anchore_grype_to_hdf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-schema"
	"github.com/mitre/hdf-mappings/go/cci"
)

// Grype report input structures

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
	Vulnerability          GrypeVulnerability           `json:"vulnerability"`
	RelatedVulnerabilities []GrypeRelatedVulnerability  `json:"relatedVulnerabilities,omitempty"`
	MatchDetails           []GrypeMatchDetail           `json:"matchDetails"`
	Artifact               GrypeArtifact                `json:"artifact"`
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
	Type    string                 `json:"type,omitempty"` // "exact-direct-match", "exact-indirect-match", "cpe-match"
	Matcher string                 `json:"matcher,omitempty"`
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

// NIST controls for vulnerability management
var nistTags = []string{"SA-11", "RA-5"}

// Severity to impact mapping
func getImpact(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 0.9
	case "high":
		return 0.7
	case "medium":
		return 0.5
	case "low":
		return 0.3
	case "negligible":
		return 0.0
	default: // unknown or empty
		return 0.5
	}
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

	jsonBytes, _ := json.Marshal(cvssData)
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

func getCCITags() []interface{} {
	// Get all CCIs that map to our NIST controls
	cciSet := make(map[string]bool)
	allCCIs := cci.GetAllCCIIDs()

	for _, cciID := range allCCIs {
		nistMappings := cci.GetCCINistMappings(cciID)
		if len(nistMappings) == 0 {
			continue
		}

		// Check if any of the CCI's NIST mappings match our tags
		for _, nistMapping := range nistMappings {
			for _, nistTag := range nistTags {
				if nistMapping == nistTag {
					cciSet[cciID] = true
					break
				}
			}
		}
	}

	// Convert set to slice
	cciTags := make([]interface{}, 0, len(cciSet))
	for cciID := range cciSet {
		cciTags = append(cciTags, cciID)
	}

	return cciTags
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
	if isIgnored {
		status = hdf.NotReviewed // Ignored by configured rules
	} else if isNegligibleOrUnknown(severity) {
		status = hdf.NotApplicable
	} else {
		status = hdf.Failed
	}

	// Build result message
	messageParts := []string{}
	if isIgnored {
		messageParts = append(messageParts, "This vulnerability was ignored by configured rules.")
	}
	if isNegligibleOrUnknown(severity) && !isIgnored {
		messageParts = append(messageParts, "Manual review required because an Anchore Grype rating severity is set to `negligible` or `unknown`.")
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

	// Get CCI tags
	cciTags := getCCITags()

	// Build tags - only include cci if not empty
	nistInterfaces := make([]interface{}, len(nistTags))
	for i, tag := range nistTags {
		nistInterfaces[i] = tag
	}

	tags := map[string]interface{}{
		"nist": nistInterfaces,
	}
	if len(cciTags) > 0 {
		tags["cci"] = cciTags
	}

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

// ConvertAnchoreGrypeToHDF converts Anchore Grype JSON to HDF
func ConvertAnchoreGrypeToHDF(input []byte) ([]byte, error) {
	// Calculate checksum of input data
	hash := sha256.Sum256(input)
	resultsChecksum := &hdf.Checksum{
		Algorithm: hdf.Sha256,
		Value:     hex.EncodeToString(hash[:]),
	}

	// Parse Grype JSON
	var grypeData GrypeReport
	if err := json.Unmarshal(input, &grypeData); err != nil {
		return nil, fmt.Errorf("invalid Anchore Grype JSON: %w", err)
	}

	// Build requirements from matches
	requirements := []hdf.EvaluatedRequirement{}

	// Process regular matches
	for _, match := range grypeData.Matches {
		requirements = append(requirements, convertMatchToRequirement(match, false))
	}

	// Process ignored matches
	for _, match := range grypeData.IgnoredMatches {
		requirements = append(requirements, convertMatchToRequirement(match, true))
	}

	// Build baseline name from source
	targetName := grypeData.Source.Target.UserInput
	if targetName == "" {
		targetName = "Anchore Grype Scan"
	}

	// Create baseline
	baseline := hdf.EvaluatedBaseline{
		Name:            targetName,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	// Build generator
	generatorName := grypeData.Descriptor.Name
	if generatorName == "" {
		generatorName = "grype"
	}
	generatorVersion := grypeData.Descriptor.Version
	if generatorVersion == "" {
		generatorVersion = "unknown"
	}

	generator := &hdf.Generator{
		Name:    generatorName,
		Version: generatorVersion,
	}

	// Build timestamp
	var timestamp *time.Time
	if grypeData.Descriptor.Timestamp != "" {
		parsedTime, err := time.Parse(time.RFC3339, grypeData.Descriptor.Timestamp)
		if err == nil {
			timestamp = &parsedTime
		}
	}

	// Build HDF results
	hdfResult := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{baseline},
		Generator: generator,
		Timestamp: timestamp,
	}

	return json.MarshalIndent(hdfResult, "", "  ")
}
