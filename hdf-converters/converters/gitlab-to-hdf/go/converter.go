package gitlab_to_hdf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// --- GitLab Security Report input structures ---

// GitLabReport is the top-level GitLab security report JSON object.
type GitLabReport struct {
	Version         string                `json:"version,omitempty"`
	Scan            *GitLabScan           `json:"scan,omitempty"`
	Vulnerabilities []GitLabVulnerability `json:"vulnerabilities"`
	Remediations    []GitLabRemediation   `json:"remediations,omitempty"`
}

// GitLabScan describes the scan that produced the report.
type GitLabScan struct {
	Analyzer  *GitLabTool `json:"analyzer,omitempty"`
	Scanner   *GitLabTool `json:"scanner,omitempty"`
	StartTime string      `json:"start_time,omitempty"`
	EndTime   string      `json:"end_time,omitempty"`
	Status    string      `json:"status,omitempty"`
	Type      string      `json:"type,omitempty"`
}

// GitLabTool describes an analyzer or scanner.
type GitLabTool struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// GitLabVulnerability is a single finding in the report.
type GitLabVulnerability struct {
	ID          string             `json:"id"`
	Name        string             `json:"name,omitempty"`
	Description string             `json:"description,omitempty"`
	Severity    string             `json:"severity,omitempty"`
	Solution    string             `json:"solution,omitempty"`
	Identifiers []GitLabIdentifier `json:"identifiers,omitempty"`
	Location    *GitLabLocation    `json:"location,omitempty"`
	Links       []GitLabLink       `json:"links,omitempty"`

	// raw is the vulnerability exactly as GitLab emitted it. GitLab carries no
	// literal source snippet, so requirement.code is the whole vulnerability
	// re-indented in place — preserving source key order and every field the
	// typed struct drops (links, identifiers[].url, location detail) so the
	// output is byte-identical to the TypeScript twin's JSON.stringify(vuln, null, 2).
	raw json.RawMessage
}

func (v *GitLabVulnerability) UnmarshalJSON(data []byte) error {
	type plain GitLabVulnerability
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*v = GitLabVulnerability(p)
	v.raw = append(json.RawMessage(nil), data...)
	return nil
}

// GitLabIdentifier is a vulnerability identifier (CWE, CVE, etc.).
type GitLabIdentifier struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
	URL   string `json:"url,omitempty"`
}

// GitLabLocation describes where a vulnerability was found.
// The "method" field is polymorphic: for SAST it's the code method name,
// for DAST it's the HTTP method. Same JSON key, different semantics per scan type.
type GitLabLocation struct {
	File            string            `json:"file,omitempty"`
	StartLine       *int              `json:"start_line,omitempty"`
	EndLine         *int              `json:"end_line,omitempty"`
	Class           string            `json:"class,omitempty"`
	Method          string            `json:"method,omitempty"`
	Hostname        string            `json:"hostname,omitempty"`
	Path            string            `json:"path,omitempty"`
	Param           string            `json:"param,omitempty"`
	Image           string            `json:"image,omitempty"`
	OperatingSystem string            `json:"operating_system,omitempty"`
	Dependency      *GitLabDependency `json:"dependency,omitempty"`
}

// GitLabDependency describes a dependency in the location.
type GitLabDependency struct {
	Package *GitLabPackage `json:"package,omitempty"`
	Version string         `json:"version,omitempty"`
}

// GitLabPackage describes a package name.
type GitLabPackage struct {
	Name string `json:"name,omitempty"`
}

// GitLabLink is a reference URL.
type GitLabLink struct {
	URL string `json:"url,omitempty"`
}

// GitLabRemediation describes an available fix.
type GitLabRemediation struct {
	Fixes   []GitLabFix `json:"fixes,omitempty"`
	Summary string      `json:"summary,omitempty"`
	Diff    string      `json:"diff,omitempty"`
}

// GitLabFix identifies which vulnerability a remediation fixes.
type GitLabFix struct {
	ID  string `json:"id,omitempty"`
	CVE string `json:"cve,omitempty"`
}

// --- Severity to impact ---

func severityToImpact(severity string) float64 {
	return hdfutil.SeverityToImpact(severity, 0.5)
}

// --- Scan type to target type ---

func scanTypeToTargetType(scanType string) hdf.TargetType {
	switch scanType {
	case "dast":
		return hdf.Application
	case "container_scanning":
		return hdf.ContainerImage
	default:
		return hdf.Repository
	}
}

// --- Scan type label ---

func scanTypeLabel(scanType string) string {
	labels := map[string]string{
		"sast":                "SAST",
		"dast":                "DAST",
		"dependency_scanning": "Dependency Scanning",
		"container_scanning":  "Container Scanning",
		"secret_detection":    "Secret Detection",
		"api_fuzzing":         "API Fuzzing",
	}
	if label, ok := labels[scanType]; ok {
		return label
	}
	return strings.ToUpper(scanType)
}

// --- NIST tag building ---

func buildNistTags(identifiers []GitLabIdentifier) []string {
	seen := make(map[string]bool)
	var controls []string
	for _, id := range identifiers {
		if strings.EqualFold(id.Type, "cwe") && id.Value != "" {
			for _, ctrl := range cwe.NISTControls(id.Value) {
				if !seen[ctrl] {
					seen[ctrl] = true
					controls = append(controls, ctrl)
				}
			}
		}
	}
	if len(controls) > 0 {
		return controls
	}
	return shared.DefaultStaticAnalysisNIST
}

// buildRefs collects external reference URLs for a vulnerability from its
// links[] and identifiers[] (e.g. CWE/CVE pages), de-duplicated so a URL that
// appears in both never shows up twice. Returns nil when the source carries none.
func buildRefs(vuln GitLabVulnerability) []hdf.Reference {
	var refs []hdf.Reference
	seen := make(map[string]bool)
	appendURL := func(u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		urlCopy := u
		refs = append(refs, hdf.Reference{URL: &urlCopy})
	}
	for _, link := range vuln.Links {
		appendURL(link.URL)
	}
	for _, id := range vuln.Identifiers {
		appendURL(id.URL)
	}
	return refs
}

// buildRemediationMap maps a vulnerability identifier (matched via a
// remediation's fixes[].id or fixes[].cve) to the remediation summary text.
// A remediation with no summary carries no guidance and is skipped.
func buildRemediationMap(remediations []GitLabRemediation) map[string][]string {
	result := make(map[string][]string)
	for _, rem := range remediations {
		if rem.Summary == "" {
			continue
		}
		for _, fix := range rem.Fixes {
			for _, key := range []string{fix.ID, fix.CVE} {
				if key != "" {
					result[key] = append(result[key], rem.Summary)
				}
			}
		}
	}
	return result
}

// --- Collect identifier tags ---

func collectIdentifierExtras(identifiers []GitLabIdentifier) map[string]interface{} {
	result := make(map[string][]string)
	for _, id := range identifiers {
		if id.Type != "" && id.Value != "" {
			key := strings.ToLower(id.Type)
			result[key] = append(result[key], id.Value)
		}
	}
	extras := make(map[string]interface{})
	for k, v := range result {
		extras[k] = hdfutil.StringsToInterfaces(v)
	}
	return extras
}

// buildVulnCode renders the raw vulnerability as indented JSON for
// requirement.code. json.Indent re-formats the original bytes in place,
// preserving source key order so the output is byte-identical to the
// TypeScript twin's JSON.stringify(vuln, null, 2).
func buildVulnCode(vuln GitLabVulnerability) string {
	if len(vuln.raw) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, vuln.raw, "", "  "); err != nil {
		return "{}"
	}
	return buf.String()
}

// buildSourceLocation promotes a finding's file locus into the structured
// requirement.sourceLocation field (machine-addressable, distinct from the
// codeDesc freetext). Ref is the source file path; Line is the start line,
// falling back to end_line only when start_line is absent. Returns nil when the
// location carries no file (e.g. DAST URL findings) so the field is omitted.
func buildSourceLocation(loc *GitLabLocation) *hdf.SourceLocation {
	if loc == nil || loc.File == "" {
		return nil
	}
	ref := loc.File
	sl := &hdf.SourceLocation{Ref: &ref}
	line := loc.StartLine
	if line == nil {
		line = loc.EndLine
	}
	if line != nil {
		l := float64(*line)
		sl.Line = &l
	}
	return sl
}

// --- Build code description by scan type ---

func buildCodeDesc(scanType string, loc *GitLabLocation) string {
	if loc == nil {
		return ""
	}

	switch scanType {
	case "sast", "secret_detection":
		return buildSASTCodeDesc(loc)
	case "dast":
		return buildDASTCodeDesc(loc)
	case "dependency_scanning":
		return buildDepScanCodeDesc(loc)
	case "container_scanning":
		return buildContainerCodeDesc(loc)
	default:
		raw, _ := json.Marshal(loc)
		return fmt.Sprintf("Location: %s", string(raw))
	}
}

func buildSASTCodeDesc(loc *GitLabLocation) string {
	var parts []string
	if loc.File != "" {
		parts = append(parts, fmt.Sprintf("File: %s", loc.File))
	}
	if loc.StartLine != nil {
		if loc.EndLine != nil && *loc.EndLine != *loc.StartLine {
			parts = append(parts, fmt.Sprintf("Line: %d-%d", *loc.StartLine, *loc.EndLine))
		} else {
			parts = append(parts, fmt.Sprintf("Line: %d", *loc.StartLine))
		}
	}
	if loc.Class != "" {
		parts = append(parts, fmt.Sprintf("Class: %s", loc.Class))
	}
	if loc.Method != "" {
		parts = append(parts, fmt.Sprintf("Method: %s", loc.Method))
	}
	return strings.Join(parts, " | ")
}

func buildDASTCodeDesc(loc *GitLabLocation) string {
	var parts []string
	if loc.Hostname != "" {
		url := loc.Hostname
		if loc.Path != "" {
			url += loc.Path
		}
		parts = append(parts, fmt.Sprintf("URL: %s", url))
	}
	if loc.Method != "" {
		parts = append(parts, fmt.Sprintf("Method: %s", loc.Method))
	}
	if loc.Param != "" {
		parts = append(parts, fmt.Sprintf("Param: %s", loc.Param))
	}
	return strings.Join(parts, " | ")
}

func buildDepScanCodeDesc(loc *GitLabLocation) string {
	var parts []string
	if loc.File != "" {
		parts = append(parts, fmt.Sprintf("File: %s", loc.File))
	}
	if loc.Dependency != nil && loc.Dependency.Package != nil && loc.Dependency.Package.Name != "" {
		pkg := loc.Dependency.Package.Name
		if loc.Dependency.Version != "" {
			pkg += "@" + loc.Dependency.Version
		}
		parts = append(parts, fmt.Sprintf("Package: %s", pkg))
	}
	return strings.Join(parts, " | ")
}

func buildContainerCodeDesc(loc *GitLabLocation) string {
	var parts []string
	if loc.Image != "" {
		parts = append(parts, fmt.Sprintf("Image: %s", loc.Image))
	}
	if loc.Dependency != nil && loc.Dependency.Package != nil && loc.Dependency.Package.Name != "" {
		pkg := loc.Dependency.Package.Name
		if loc.Dependency.Version != "" {
			pkg += "@" + loc.Dependency.Version
		}
		parts = append(parts, fmt.Sprintf("Package: %s", pkg))
	}
	return strings.Join(parts, " | ")
}

// ConvertGitlabToHDF converts a GitLab Security Report JSON to HDF Results.
func ConvertGitlabToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if err := shared.ValidateJSONSize(input, "gitlab", 0); err != nil {
		return nil, fmt.Errorf("gitlab: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	var report GitLabReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("invalid GitLab JSON: %w", err)
	}

	scanType := "sast"
	scannerName := "GitLab Security Scanner"
	scannerVersion := ""
	startTime := ""

	if report.Scan != nil {
		if report.Scan.Type != "" {
			scanType = report.Scan.Type
		}
		if report.Scan.Scanner != nil {
			if report.Scan.Scanner.Name != "" {
				scannerName = report.Scan.Scanner.Name
			}
			scannerVersion = report.Scan.Scanner.Version
		}
		startTime = report.Scan.StartTime
	}

	limitedVulns := shared.LimitSliceWithWarning(report.Vulnerabilities, 0, "vulnerability")

	remediationMap := buildRemediationMap(report.Remediations)

	var requirements []hdf.EvaluatedRequirement

	for _, vuln := range limitedVulns {
		identifiers := vuln.Identifiers

		// Build NIST tags
		nistTags := buildNistTags(identifiers)
		cciTags := cci.NISTToCCI(nistTags)

		// Build extra tags from identifiers
		extras := collectIdentifierExtras(identifiers)
		var tags map[string]interface{}
		if len(extras) > 0 {
			tags = shared.BuildNISTCCITagsWithExtras(nistTags, cciTags, extras)
		} else {
			tags = shared.BuildNISTCCITags(nistTags, cciTags)
		}
		shared.MarkUnratedSeverity(tags, vuln.Severity)

		// Build descriptions
		var descriptions []hdf.Description
		if vuln.Description != "" {
			descriptions = append(descriptions, hdf.Description{
				Label: "default",
				Data:  vuln.Description,
			})
		}
		if vuln.Solution != "" {
			descriptions = append(descriptions, hdf.Description{
				Label: "check",
				Data:  vuln.Solution,
			})
		}
		seenRem := make(map[string]bool)
		for _, summary := range remediationMap[vuln.ID] {
			if seenRem[summary] {
				continue
			}
			seenRem[summary] = true
			descriptions = append(descriptions, hdf.Description{
				Label: "remediation",
				Data:  summary,
			})
		}

		// Build result
		result := hdf.RequirementResult{
			Status:   hdf.Failed,
			CodeDesc: buildCodeDesc(scanType, vuln.Location),
		}
		if startTime != "" {
			ts := hdfutil.ParseTimestamp(startTime)
			if !ts.IsZero() {
				result.StartTime = ts
			}
		}

		impact := severityToImpact(vuln.Severity)

		title := vuln.Name
		if title == "" {
			title = vuln.ID
		}

		req := hdf.EvaluatedRequirement{
			ID:                 vuln.ID,
			Title:              &title,
			Impact:             impact,
			Code:               hdfutil.Ptr(buildVulnCode(vuln)),
			Results:            []hdf.RequirementResult{result},
			Tags:               tags,
			Descriptions:       descriptions,
			Refs:               buildRefs(vuln),
			ControlType:        shared.DeriveControlTypeFromTags(nistTags),
			VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
			SourceLocation:     buildSourceLocation(vuln.Location),
		}

		requirements = append(requirements, req)
	}

	label := scanTypeLabel(scanType)

	if len(requirements) == 0 {
		ts := time.Now().UTC()
		if startTime != "" {
			if parsed := hdfutil.ParseTimestamp(startTime); !parsed.IsZero() {
				ts = parsed
			}
		}
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"gitlab-no-findings",
				fmt.Sprintf("GitLab %s scan via %s reported zero findings.", label, scannerName),
				ts,
			),
		}
	}

	baselineTitle := fmt.Sprintf("GitLab %s Security Scan", label)
	summary := fmt.Sprintf("Scanner: %s", scannerName)
	if scannerVersion != "" {
		summary += fmt.Sprintf(" v%s", scannerVersion)
	}
	scanLabel := "GitLab Security Scan"

	baseline := hdf.EvaluatedBaseline{
		Name:            scanLabel,
		Title:           &baselineTitle,
		Summary:         &summary,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	// Build targets
	targetType := scanTypeToTargetType(scanType)
	targets := []hdf.Component{
		{Name: scannerName, Type: targetType},
	}

	// Compute timestamp before building results
	var timestamp *time.Time
	if report.Scan != nil && report.Scan.EndTime != "" {
		ts := hdfutil.ParseTimestamp(report.Scan.EndTime)
		if !ts.IsZero() {
			timestamp = &ts
		}
	}

	hdfResult := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "gitlab-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         scannerName,
		ToolVersion:      scannerVersion,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       targets,
		Timestamp:        timestamp,
	})

	return hdfResult, nil
}
