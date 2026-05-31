package burpsuite

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// --- BurpSuite XML input structures ---

// BurpIssues is the top-level BurpSuite XML export structure.
type BurpIssues struct {
	XMLName     xml.Name    `xml:"issues"`
	BurpVersion string      `xml:"burpVersion,attr"`
	ExportTime  string      `xml:"exportTime,attr"`
	Issues      []BurpIssue `xml:"issue"`
}

// BurpIssue represents a single issue in the BurpSuite export.
type BurpIssue struct {
	SerialNumber                 string   `xml:"serialNumber"`
	Type                         string   `xml:"type"`
	Name                         string   `xml:"name"`
	Host                         BurpHost `xml:"host"`
	Path                         string   `xml:"path"`
	Location                     string   `xml:"location"`
	Severity                     string   `xml:"severity"`
	Confidence                   string   `xml:"confidence"`
	IssueBackground              string   `xml:"issueBackground"`
	RemediationBackground        string   `xml:"remediationBackground"`
	References                   string   `xml:"references"`
	VulnerabilityClassifications string   `xml:"vulnerabilityClassifications"`
	IssueDetail                  string   `xml:"issueDetail"`
}

// BurpHost represents the host element with ip attribute.
type BurpHost struct {
	IP   string `xml:"ip,attr"`
	Text string `xml:",chardata"`
}

// --- Severity to impact mapping ---
// BurpSuite maps "information" to 0.3 (not the standard 0.0) and defaults to 0.3.

var burpsuiteAliases = map[string]float64{
	"information": 0.3,
}

// getImpact maps BurpSuite severity strings to HDF impact values.
func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, burpsuiteAliases, 0.3)
}

// --- CWE parsing ---

// parseCWEIDs extracts CWE identifiers from the vulnerabilityClassifications HTML.
// Returns CWE-prefixed IDs (e.g., ["CWE-79"]) for use in tags and MapCWEToNIST.
func parseCWEIDs(html string) []string {
	ids := hdfutil.ExtractCWEIDs(html)
	if len(ids) == 0 {
		return nil
	}
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = "CWE-" + id
	}
	return result
}

// --- Format code desc ---

// formatCodeDesc builds a formatted code description string from issue fields,
// matching the heimdall2 BurpSuite mapper pattern.
func formatCodeDesc(hostIP, hostURL, location, issueDetail, confidence string) string {
	parts := []string{}

	parts = append(parts, fmt.Sprintf("Host: ip: %s, url: %s", hostIP, hostURL))

	parts = append(parts, fmt.Sprintf("Location: %s", hdfutil.StripHTML(location)))

	if issueDetail != "" {
		parts = append(parts, fmt.Sprintf("issueDetail: %s", hdfutil.StripHTML(issueDetail)))
	}

	parts = append(parts, fmt.Sprintf("confidence: %s", confidence))

	return strings.Join(parts, "\n") + "\n"
}

// --- Timestamp parsing ---

// parseBurpTimestamp parses BurpSuite's "Thu Feb 27 09:28:17 EST 2020" format.
func parseBurpTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// BurpSuite format: "Mon Jan 02 15:04:05 MST 2006"
	if t, err := time.Parse("Mon Jan 02 15:04:05 MST 2006", s); err == nil {
		return t
	}
	// Try shorter format without timezone: "Mon Jan 2 15:04:05 2006"
	if t, err := time.Parse("Mon Jan 2 15:04:05 2006", s); err == nil {
		return t
	}
	return hdfutil.ParseTimestamp(s)
}

// --- Main converter ---

// ConvertBurpsuiteToHDF converts BurpSuite XML export to HDF Results.
func ConvertBurpsuiteToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("burpsuite: empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, fmt.Errorf("burpsuite: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	var burpData BurpIssues
	if err := xml.Unmarshal(input, &burpData); err != nil {
		return nil, fmt.Errorf("failed to parse BurpSuite XML: %w", err)
	}

	limitedIssues := shared.LimitSliceWithWarning(burpData.Issues, 0, "issue")

	// Group issues by type (preserving insertion order)
	order := []string{}
	groups := map[string][]BurpIssue{}
	for _, issue := range limitedIssues {
		if _, seen := groups[issue.Type]; !seen {
			order = append(order, issue.Type)
		}
		groups[issue.Type] = append(groups[issue.Type], issue)
	}

	// Build requirements from grouped issues
	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, issueType := range order {
		requirements[i] = buildRequirement(issueType, groups[issueType], burpData.ExportTime)
	}

	// Determine target from the first issue's host
	targetName := "Unknown"
	if len(limitedIssues) > 0 {
		targetName = strings.TrimSpace(limitedIssues[0].Host.Text)
	}

	// Build baseline
	title := fmt.Sprintf("BurpSuite Scan: %s", targetName)
	baseline := hdf.EvaluatedBaseline{
		Name:            "BurpSuite Scan",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	// Compute timestamp before building results
	var timestamp *time.Time
	if burpData.ExportTime != "" {
		ts := parseBurpTimestamp(burpData.ExportTime)
		if !ts.IsZero() {
			timestamp = &ts
		}
	}

	hdfResult := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "burpsuite-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "BurpSuite",
		ToolVersion:      burpData.BurpVersion,
		ToolFormat:       "XML",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{
				Name: targetName,
				Type: hdf.Application,
			},
		},
		Timestamp: timestamp,
	})

	return hdfResult, nil
}

// buildRequirement converts a group of issues sharing a type into one
// EvaluatedRequirement with multiple results.
func buildRequirement(issueType string, issues []BurpIssue, exportTime string) hdf.EvaluatedRequirement {
	rep := issues[0]

	// Parse CWE IDs from vulnerabilityClassifications HTML
	cweIDs := parseCWEIDs(rep.VulnerabilityClassifications)

	// Map CWE to NIST
	nist := shared.MapCWEToNIST(cweIDs, shared.DefaultStaticAnalysisNIST)
	cciTags := cci.NISTToCCI(nist)

	// Build extra tags
	extras := map[string]interface{}{}
	if len(cweIDs) > 0 {
		cweStr := strings.Join(cweIDs, ", ")
		extras["cweid"] = cweStr
	}
	if rep.Confidence != "" {
		extras["confidence"] = rep.Confidence
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	// Build descriptions
	var descriptions []hdf.Description

	// Default description (required minimum 1 with "default" label)
	defaultData := rep.Name
	if rep.IssueBackground != "" {
		defaultData = hdfutil.StripHTML(rep.IssueBackground)
	}
	descriptions = append(descriptions, hdf.Description{
		Label: "default",
		Data:  defaultData,
	})

	// Check description from issueBackground
	if rep.IssueBackground != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "check",
			Data:  hdfutil.StripHTML(rep.IssueBackground),
		})
	}

	// Fix description from remediationBackground
	if rep.RemediationBackground != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  hdfutil.StripHTML(rep.RemediationBackground),
		})
	}

	// Build results — one per issue in the group
	results := make([]hdf.RequirementResult, len(issues))
	for i, issue := range issues {
		codeDesc := formatCodeDesc(
			issue.Host.IP,
			strings.TrimSpace(issue.Host.Text),
			issue.Location,
			issue.IssueDetail,
			issue.Confidence,
		)
		results[i] = hdf.RequirementResult{
			Status:   hdf.Failed,
			CodeDesc: codeDesc,
		}
	}

	impact := getImpact(rep.Severity)

	return hdf.EvaluatedRequirement{
		ID:                 issueType,
		Title:              &rep.Name,
		Impact:             impact,
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}
