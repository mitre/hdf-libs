package fortify

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
	"github.com/mitre/hdf-mappings/go/cci"
	hdf "github.com/mitre/hdf-schema"
)

const (
	nistReferenceName = "Standards Mapping - NIST Special Publication 800-53 Revision 4"
)

// nistPattern matches NIST 800-53 control identifiers like "SI-10", "AC-2".
var nistPattern = regexp.MustCompile(`[a-zA-Z]{2}-\d+`)

// ConvertFortifyToHDF converts Fortify FVDL XML to HDF format.
func ConvertFortifyToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("fortify: empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, fmt.Errorf("fortify: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	var fvdl FVDL
	if err := xml.Unmarshal(input, &fvdl); err != nil {
		return nil, fmt.Errorf("failed to parse Fortify FVDL: %w", err)
	}

	// Build snippet lookup: snippet ID -> Snippet
	snippetMap := buildSnippetMap(fvdl.Snippets.Snippet)

	// Build description lookup: classID -> Description
	descMap := make(map[string]*Description)
	for i := range fvdl.Descriptions {
		descMap[fvdl.Descriptions[i].ClassID] = &fvdl.Descriptions[i]
	}

	// Group vulnerabilities by ClassID
	vulnsByClassID := groupVulnsByClassID(fvdl.Vulnerabilities.Vulnerability)

	// Build requirements — one per Description classID
	limitedDescs := shared.LimitSliceWithWarning(fvdl.Descriptions, 0, "description")

	requirements := make([]hdf.EvaluatedRequirement, len(limitedDescs))
	for i, desc := range limitedDescs {
		vulns := vulnsByClassID[desc.ClassID]
		requirements[i] = buildRequirement(&desc, vulns, snippetMap, &fvdl)
	}

	// Build baseline
	title := "Fortify Static Analyzer Scan"
	summary := fmt.Sprintf("Fortify Static Analyzer Scan of UUID: %s", fvdl.UUID)
	version := fvdl.EngineData.EngineVersion
	status := "loaded"

	baseline := hdf.EvaluatedBaseline{
		Name:            "Fortify Scan",
		Title:           &title,
		Summary:         &summary,
		Version:         &version,
		Status:          &status,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	// Parse timestamp from CreatedTS
	timestamp := parseCreatedTS(fvdl.CreatedTS)

	targetName := fvdl.Build.SourceBasePath
	if targetName == "" {
		targetName = fvdl.Build.BuildID
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "fortify-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Fortify",
		ToolFormat:       "FVDL",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{Name: targetName, Type: hdf.Repository},
		},
		Timestamp: &timestamp,
	}), nil
}

// buildSnippetMap creates a map from snippet ID to Snippet for quick lookup.
func buildSnippetMap(snippets []Snippet) map[string]*Snippet {
	m := make(map[string]*Snippet, len(snippets))
	for i := range snippets {
		m[snippets[i].ID] = &snippets[i]
	}
	return m
}

// groupVulnsByClassID groups vulnerabilities by their ClassInfo.ClassID.
func groupVulnsByClassID(vulns []Vulnerability) map[string][]Vulnerability {
	groups := make(map[string][]Vulnerability)
	for _, vuln := range vulns {
		groups[vuln.ClassInfo.ClassID] = append(groups[vuln.ClassInfo.ClassID], vuln)
	}
	return groups
}

// buildRequirement creates an EvaluatedRequirement from a Description and
// its associated vulnerabilities.
func buildRequirement(desc *Description, vulns []Vulnerability, snippetMap map[string]*Snippet, fvdl *FVDL) hdf.EvaluatedRequirement {
	// Extract NIST tags from Description References
	nistTags := extractNISTFromReferences(desc.References.Reference)
	if len(nistTags) == 0 {
		nistTags = shared.DefaultStaticAnalysisNIST
	}
	cciTags := cci.NISTToCCI(nistTags)
	tags := shared.BuildNISTCCITags(nistTags, cciTags)

	// Title from Abstract (HTML stripped)
	titleStr := hdfutil.StripHTML(desc.Abstract)

	// Default description from Explanation (HTML stripped)
	explanationText := hdfutil.StripHTML(desc.Explanation)
	if explanationText == "" {
		explanationText = titleStr
	}
	descriptions := []hdf.Description{
		{Label: "default", Data: explanationText},
	}

	// Fix description from Recommendations
	if desc.Recommendations != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  hdfutil.StripHTML(desc.Recommendations),
		})
	}

	// Impact from the first vulnerability's DefaultSeverity / 5
	impact := 0.0
	if len(vulns) > 0 {
		impact = vulns[0].ClassInfo.DefaultSeverity / 5.0
	}

	// Build results — one per vulnerability instance
	results := buildResults(vulns, snippetMap, fvdl)

	return hdf.EvaluatedRequirement{
		ID:           desc.ClassID,
		Title:        &titleStr,
		Impact:       impact,
		Tags:         tags,
		Descriptions: descriptions,
		Results:      results,
	}
}

// buildResults creates one RequirementResult per vulnerability instance.
func buildResults(vulns []Vulnerability, snippetMap map[string]*Snippet, fvdl *FVDL) []hdf.RequirementResult {
	limitedVulns := shared.LimitSliceWithWarning(vulns, 0, "vulnerability")

	results := make([]hdf.RequirementResult, 0, len(limitedVulns))
	for _, vuln := range limitedVulns {
		codeDesc := buildCodeDesc(&vuln, snippetMap)
		startTime := parseCreatedTS(fvdl.CreatedTS)

		results = append(results, hdf.RequirementResult{
			Status:    hdf.Failed,
			CodeDesc:  codeDesc,
			StartTime: startTime,
		})
	}
	return results
}

// buildCodeDesc creates a code description from vulnerability trace data and
// associated snippets.
func buildCodeDesc(vuln *Vulnerability, snippetMap map[string]*Snippet) string {
	var parts []string

	for _, entry := range vuln.AnalysisInfo.Unified.Trace.Primary.Entries {
		if entry.Node == nil {
			continue
		}
		snippetID := entry.Node.SourceLocation.Snippet
		if snippetID == "" {
			// Use file + line as fallback
			path := entry.Node.SourceLocation.Path
			line := entry.Node.SourceLocation.Line
			if path != "" {
				parts = append(parts, fmt.Sprintf("Path: %s\nLine: %s", path, line))
			}
			continue
		}
		snippet, ok := snippetMap[snippetID]
		if !ok {
			continue
		}
		parts = append(parts, formatSnippet(snippet))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("ClassID: %s, InstanceID: %s", vuln.ClassInfo.ClassID, vuln.InstanceInfo.InstanceID)
	}

	return strings.Join(parts, "\n")
}

// formatSnippet formats a code snippet for display.
func formatSnippet(s *Snippet) string {
	text := strings.TrimSpace(s.Text)
	return fmt.Sprintf("Path: %s\nStartLine: %s, EndLine: %s\nCode:\n%s", s.File, s.StartLine, s.EndLine, text)
}

// extractNISTFromReferences finds the NIST 800-53 reference in the Description
// and extracts the control identifier (e.g., "SI-10").
func extractNISTFromReferences(refs []Reference) []string {
	for _, ref := range refs {
		if ref.Author == nistReferenceName {
			matches := nistPattern.FindAllString(ref.Title, -1)
			if len(matches) > 0 {
				return matches
			}
		}
	}
	return nil
}

// parseCreatedTS converts a CreatedTS element into a time.Time.
func parseCreatedTS(ts CreatedTS) time.Time {
	if ts.Date == "" {
		return time.Now().UTC()
	}
	combined := fmt.Sprintf("%s %s", ts.Date, ts.Time)
	t, err := time.Parse("2006-01-02 15:04:05", combined)
	if err != nil {
		return time.Now().UTC()
	}
	return t
}
