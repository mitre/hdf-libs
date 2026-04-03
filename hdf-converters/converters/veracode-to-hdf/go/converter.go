// Package veracode converts Veracode DetailedReport XML to HDF format.
//
// Veracode reports contain two types of findings:
//   - CWE-based controls: Static analysis findings grouped by severity and CWE category
//   - CVE-based controls: Software Composition Analysis (SCA) findings from vulnerable components
//
// Both types are merged into a single baseline with all requirements.
package veracode

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/mitre/hdf-mappings/go/cci"
	"github.com/mitre/hdf-mappings/go/cwe"
	hdf "github.com/mitre/hdf-schema"
)

// veracodeSeverityToImpact maps Veracode severity levels (0-5) to HDF impact values.
// Follows the heimdall2 IMPACT_MAPPING.

var veracodeAliases = map[string]float64{
	"5": 0.9,
	"4": 0.7,
	"3": 0.5,
	"2": 0.3,
	"1": 0.1,
	"0": 0.0,
}

func veracodeSeverityToImpact(severity string) float64 {
	return shared.SeverityToImpactWithAliases(severity, veracodeAliases, 0.1)
}

// XML structures for Veracode DetailedReport

// DetailedReport is the root element of a Veracode detailed report XML.
type DetailedReport struct {
	XMLName                xml.Name                `xml:"detailedreport"`
	AppName                string                  `xml:"app_name,attr"`
	PolicyName             string                  `xml:"policy_name,attr"`
	PolicyVersion          string                  `xml:"policy_version,attr"`
	FirstBuildSubmitted    string                  `xml:"first_build_submitted_date,attr"`
	TotalFlaws             string                  `xml:"total_flaws,attr"`
	FlawsNotMitigated      string                  `xml:"flaws_not_mitigated,attr"`
	StaticAnalysis         *StaticAnalysis         `xml:"static-analysis"`
	Severities             []Severity              `xml:"severity"`
	SoftwareCompositionSCA *SoftwareCompositionSCA `xml:"software_composition_analysis"`
}

// StaticAnalysis contains static analysis module information.
type StaticAnalysis struct {
	Modules Modules `xml:"modules"`
}

// Modules contains the list of scanned modules.
type Modules struct {
	Module []Module `xml:"module"`
}

// Module represents a scanned module (e.g., WAR file).
type Module struct {
	Name string `xml:"name,attr"`
}

// Severity groups categories by severity level (0-5).
type Severity struct {
	Level      string     `xml:"level,attr"`
	Categories []Category `xml:"category"`
}

// Category represents a CWE-based finding category.
type Category struct {
	CategoryID      string          `xml:"categoryid,attr"`
	CategoryName    string          `xml:"categoryname,attr"`
	PCIRelated      string          `xml:"pcirelated,attr"`
	Desc            Desc            `xml:"desc"`
	Recommendations Recommendations `xml:"recommendations"`
	CWEs            []CWE           `xml:"cwe"`
}

// Desc contains description paragraphs.
type Desc struct {
	Para []Para `xml:"para"`
}

// Recommendations contains recommendation paragraphs.
type Recommendations struct {
	Para []RecPara `xml:"para"`
}

// RecPara is a paragraph with optional bullet items.
type RecPara struct {
	Text        string       `xml:"text,attr"`
	BulletItems []BulletItem `xml:"bulletitem"`
}

// BulletItem is a bullet list item within recommendations.
type BulletItem struct {
	Text string `xml:"text,attr"`
}

// Para is a text paragraph.
type Para struct {
	Text string `xml:"text,attr"`
}

// CWE represents a CWE entry with description, static flaws, and category metadata.
type CWE struct {
	CWEID       string      `xml:"cweid,attr"`
	CWEName     string      `xml:"cwename,attr"`
	PCIRelated  string      `xml:"pcirelated,attr"`
	OWASP       string      `xml:"owasp,attr"`
	SANS        string      `xml:"sans,attr"`
	CERTC       string      `xml:"certc,attr"`
	CERTCPP     string      `xml:"certcpp,attr"`
	CERTJava    string      `xml:"certjava,attr"`
	OWASPMobile string      `xml:"owaspmobile,attr"`
	Description CWEDesc     `xml:"description"`
	StaticFlaws StaticFlaws `xml:"staticflaws"`
}

// CWEDesc wraps the CWE description text.
type CWEDesc struct {
	Text CWEDescText `xml:"text"`
}

// CWEDescText is the description text element.
type CWEDescText struct {
	Text string `xml:"text,attr"`
}

// StaticFlaws contains the list of static analysis flaws.
type StaticFlaws struct {
	Flaws []Flaw `xml:"flaw"`
}

// Flaw represents a single static analysis finding.
type Flaw struct {
	Severity                 string `xml:"severity,attr"`
	CategoryName             string `xml:"categoryname,attr"`
	Count                    string `xml:"count,attr"`
	IssueID                  string `xml:"issueid,attr"`
	Module                   string `xml:"module,attr"`
	Type                     string `xml:"type,attr"`
	Description              string `xml:"description,attr"`
	Note                     string `xml:"note,attr"`
	CWEID                    string `xml:"cweid,attr"`
	RemediationEffort        string `xml:"remediationeffort,attr"`
	ExploitLevel             string `xml:"exploitLevel,attr"`
	CategoryID               string `xml:"categoryid,attr"`
	PCIRelated               string `xml:"pcirelated,attr"`
	DateFirstOccurrence      string `xml:"date_first_occurrence,attr"`
	RemediationStatus        string `xml:"remediation_status,attr"`
	CIAImpact                string `xml:"cia_impact,attr"`
	GracePeriodExpires       string `xml:"grace_period_expires,attr"`
	AffectsPolicyCompliance  string `xml:"affects_policy_compliance,attr"`
	MitigationStatus         string `xml:"mitigation_status,attr"`
	MitigationStatusDesc     string `xml:"mitigation_status_desc,attr"`
	SourceFile               string `xml:"sourcefile,attr"`
	Line                     string `xml:"line,attr"`
	SourceFilePath           string `xml:"sourcefilepath,attr"`
	Scope                    string `xml:"scope,attr"`
	FunctionPrototype        string `xml:"functionprototype,attr"`
	FunctionRelativeLocation string `xml:"functionrelativelocation,attr"`
}

// SoftwareCompositionSCA is the SCA section of a Veracode report.
type SoftwareCompositionSCA struct {
	VulnerableComponents VulnerableComponents `xml:"vulnerable_components"`
}

// VulnerableComponents contains the list of SCA components.
type VulnerableComponents struct {
	Components []Component `xml:"component"`
}

// Component represents a third-party software component.
type Component struct {
	ComponentID                      string             `xml:"component_id,attr"`
	FileName                         string             `xml:"file_name,attr"`
	SHA1                             string             `xml:"sha1,attr"`
	Vulnerabilities                  string             `xml:"vulnerabilities,attr"`
	MaxCVSSScore                     string             `xml:"max_cvss_score,attr"`
	Version                          string             `xml:"version,attr"`
	Library                          string             `xml:"library,attr"`
	LibraryID                        string             `xml:"library_id,attr"`
	Vendor                           string             `xml:"vendor,attr"`
	Description                      string             `xml:"description,attr"`
	AddedDate                        string             `xml:"added_date,attr"`
	ComponentAffectsPolicyCompliance string             `xml:"component_affects_policy_compliance,attr"`
	FilePaths                        ComponentFilePaths `xml:"file_paths"`
	VulnerabilityList                VulnerabilityList  `xml:"vulnerabilities"`
}

// ComponentFilePaths wraps the list of file paths for a component.
type ComponentFilePaths struct {
	FilePath []ComponentFilePath `xml:"file_path"`
}

// ComponentFilePath is a single file path value.
type ComponentFilePath struct {
	Value string `xml:"value,attr"`
}

// VulnerabilityList wraps the list of CVE vulnerabilities for a component.
type VulnerabilityList struct {
	Vulnerabilities []Vulnerability `xml:"vulnerability"`
}

// Vulnerability represents a single CVE vulnerability in an SCA component.
type Vulnerability struct {
	CVEID          string `xml:"cve_id,attr"`
	CVSSScore      string `xml:"cvss_score,attr"`
	Severity       string `xml:"severity,attr"`
	CWEID          string `xml:"cwe_id,attr"`
	FirstFoundDate string `xml:"first_found_date,attr"`
	CVESummary     string `xml:"cve_summary,attr"`
	SeverityDesc   string `xml:"severity_desc,attr"`
}

// SummaryReport is the root element of a Veracode summary report (not supported).
type SummaryReport struct {
	XMLName xml.Name `xml:"summaryreport"`
}

// unmarshalVeracodeXML decodes XML with support for ISO-8859-1 encoding.
// Go's xml.Unmarshal does not handle non-UTF-8 encodings by default;
// we provide a CharsetReader that treats ISO-8859-1 as a byte-passthrough
// since Veracode XMLs use XML entities for non-ASCII characters.
func unmarshalVeracodeXML(input []byte, v interface{}) error {
	decoder := xml.NewDecoder(bytes.NewReader(input))
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "iso-8859-1", "latin1", "latin-1":
			// ISO-8859-1 is a superset of ASCII. Veracode uses XML entities
			// for characters outside ASCII, so a pass-through reader is safe.
			return &latin1Reader{r: input}, nil
		case "utf-8", "":
			return input, nil
		default:
			return nil, fmt.Errorf("unsupported charset: %s", charset)
		}
	}
	return decoder.Decode(v)
}

// latin1Reader converts ISO-8859-1 bytes to UTF-8 on the fly.
type latin1Reader struct {
	r   io.Reader
	buf [1024]byte
}

func (r *latin1Reader) Read(p []byte) (int, error) {
	// Read raw bytes
	max := len(r.buf)
	if max > len(p)/utf8.UTFMax {
		max = len(p) / utf8.UTFMax
	}
	if max == 0 {
		max = 1
	}
	n, err := r.r.Read(r.buf[:max])
	if n == 0 {
		return 0, err
	}

	// Convert each byte to its UTF-8 representation
	j := 0
	for i := 0; i < n; i++ {
		j += utf8.EncodeRune(p[j:], rune(r.buf[i]))
	}
	return j, err
}

// ConvertVeracodeToHDF converts Veracode DetailedReport XML to HDF format.
func ConvertVeracodeToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("veracode: empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, fmt.Errorf("veracode: %w", err)
	}

	// Check for summary report — not supported
	var summary SummaryReport
	if err := unmarshalVeracodeXML(input, &summary); err == nil && summary.XMLName.Local == "summaryreport" {
		return nil, fmt.Errorf("veracode: summary reports are not supported; use a detailed report")
	}

	checksum := shared.InputChecksum(input)

	var report DetailedReport
	if err := unmarshalVeracodeXML(input, &report); err != nil {
		return nil, fmt.Errorf("veracode: failed to parse XML: %w", err)
	}

	if report.XMLName.Local != "detailedreport" {
		return nil, fmt.Errorf("veracode: expected <detailedreport> root element, got <%s>", report.XMLName.Local)
	}

	// Build CWE-based requirements from severity categories
	cweRequirements := buildCWERequirements(report.Severities, report.FirstBuildSubmitted)

	// Build CVE-based requirements from SCA components
	cveRequirements := buildCVERequirements(report.SoftwareCompositionSCA, report.FirstBuildSubmitted)

	// Merge all requirements into one baseline
	allRequirements := append(cweRequirements, cveRequirements...)

	baseline := hdf.EvaluatedBaseline{
		Name:            "Veracode Scan",
		Requirements:    allRequirements,
		ResultsChecksum: checksum,
	}

	// Set title from static analysis module name if available
	if report.StaticAnalysis != nil && len(report.StaticAnalysis.Modules.Module) > 0 {
		title := report.StaticAnalysis.Modules.Module[0].Name
		baseline.Title = &title
	}

	policyName := report.PolicyName
	if policyName != "" {
		baseline.Version = &report.PolicyVersion
		baseline.Summary = &policyName
	}

	// Parse timestamp
	var timestamp *time.Time
	if report.FirstBuildSubmitted != "" {
		if t := parseVeracodeTimestamp(report.FirstBuildSubmitted); !t.IsZero() {
			timestamp = &t
		}
	}

	targetName := report.AppName
	if targetName == "" {
		targetName = "Veracode Application"
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "veracode-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Veracode",
		ToolFormat:       "XML",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{Name: targetName, Type: hdf.CopyrightApplication},
		},
		Timestamp: timestamp,
	}), nil
}

// buildCWERequirements creates HDF requirements from CWE-based severity categories.
// Each category becomes one requirement; each flaw within becomes one result.
func buildCWERequirements(severities []Severity, firstBuildDate string) []hdf.EvaluatedRequirement {
	var requirements []hdf.EvaluatedRequirement

	for _, sev := range severities {
		impact := veracodeSeverityToImpact(sev.Level)

		for _, cat := range sev.Categories {
			req := buildCWERequirement(cat, impact, firstBuildDate)
			requirements = append(requirements, req)
		}
	}

	return requirements
}

// buildCWERequirement creates a single requirement from a CWE category.
func buildCWERequirement(cat Category, impact float64, firstBuildDate string) hdf.EvaluatedRequirement {
	// Collect CWE IDs for NIST mapping
	cweIDs := make([]string, 0, len(cat.CWEs))
	for _, c := range cat.CWEs {
		if c.CWEID != "" {
			cweIDs = append(cweIDs, c.CWEID)
		}
	}

	nist := shared.MapCWEToNIST(cweIDs, shared.DefaultRemediationNIST)
	cciTags := cci.NISTToCCI(nist)

	// Build CWE data string for tags
	cweData := formatCWEData(cat.CWEs)
	cweDescStr := formatCWEDesc(cat.CWEs)

	extras := map[string]interface{}{}
	if cweData != "" {
		extras["cweid"] = cweData
	}
	if cweDescStr != "" {
		extras["cweDescription"] = cweDescStr
	}

	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	// Build descriptions
	descriptions := []hdf.Description{
		{Label: "default", Data: formatDesc(cat.Desc)},
	}

	// Add fix/recommendation description
	recText := formatRecommendations(cat.Recommendations)
	if recText != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  recText,
		})
	}

	// Collect all flaws from all CWEs under this category
	var results []hdf.RequirementResult
	for _, c := range cat.CWEs {
		limited := shared.LimitSliceWithWarning(c.StaticFlaws.Flaws, 0, "flaw")
		for _, flaw := range limited {
			result := buildFlawResult(flaw, firstBuildDate)
			results = append(results, result)
		}
	}

	// Build source location from flaw source files
	sourceRef := formatSourceLocation(cat.CWEs)

	title := cat.CategoryName
	req := hdf.EvaluatedRequirement{
		ID:           cat.CategoryID,
		Title:        &title,
		Impact:       impact,
		Tags:         tags,
		Descriptions: descriptions,
		Results:      results,
	}

	if sourceRef != "" {
		req.SourceLocation = &hdf.SourceLocation{
			Ref: &sourceRef,
		}
	}

	return req
}

// buildFlawResult creates an HDF RequirementResult from a static analysis flaw.
func buildFlawResult(flaw Flaw, firstBuildDate string) hdf.RequirementResult {
	codeDesc := formatFlawCodeDesc(flaw)

	startTime := parseVeracodeTimestamp(firstBuildDate)
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}

	result := hdf.RequirementResult{
		Status:    hdf.Failed,
		CodeDesc:  codeDesc,
		StartTime: startTime,
	}

	// Add exploitability note as message if present
	// Note: Flaw.Note field can contain an exploitability message
	if flaw.Note != "" {
		result.Message = &flaw.Note
	}

	return result
}

// buildCVERequirements creates HDF requirements from SCA vulnerable components.
// CVEs are grouped across components — each unique CVE becomes one requirement,
// with one result per affected component.
func buildCVERequirements(sca *SoftwareCompositionSCA, firstBuildDate string) []hdf.EvaluatedRequirement {
	if sca == nil {
		return nil
	}

	// Group vulnerabilities by CVE ID across all components
	type cveEntry struct {
		vuln       Vulnerability
		components []Component
	}

	cveOrder := []string{}
	cveMap := map[string]*cveEntry{}

	for _, comp := range sca.VulnerableComponents.Components {
		if comp.Vulnerabilities == "0" {
			continue
		}
		for _, vuln := range comp.VulnerabilityList.Vulnerabilities {
			if vuln.CVEID == "" {
				continue
			}
			if entry, exists := cveMap[vuln.CVEID]; exists {
				entry.components = append(entry.components, comp)
			} else {
				cveOrder = append(cveOrder, vuln.CVEID)
				cveMap[vuln.CVEID] = &cveEntry{
					vuln:       vuln,
					components: []Component{comp},
				}
			}
		}
	}

	requirements := make([]hdf.EvaluatedRequirement, 0, len(cveOrder))
	for _, cveID := range cveOrder {
		entry := cveMap[cveID]
		req := buildCVERequirement(entry.vuln, entry.components, firstBuildDate)
		requirements = append(requirements, req)
	}

	return requirements
}

// buildCVERequirement creates a single requirement from a CVE across its affected components.
func buildCVERequirement(vuln Vulnerability, components []Component, firstBuildDate string) hdf.EvaluatedRequirement {
	impact := veracodeSeverityToImpact(vuln.Severity)

	// Map CWE to NIST — CVE entries may have cwe_id like "CWE-77"
	var nist []string
	if vuln.CWEID != "" {
		cweIDs := []string{strings.TrimPrefix(vuln.CWEID, "CWE-")}
		nist = shared.MapCWEToNIST(cweIDs, shared.DefaultRemediationNIST)
	} else {
		nist = shared.DefaultRemediationNIST
	}
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{}
	if vuln.CWEID != "" {
		extras["cwe"] = vuln.CWEID
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	// Build results: one per affected component
	results := make([]hdf.RequirementResult, len(components))
	for i, comp := range components {
		results[i] = buildSCAResult(comp, firstBuildDate)
	}

	// Build source location from component file paths
	var filePaths []string
	for _, comp := range components {
		for _, fp := range comp.FilePaths.FilePath {
			if fp.Value != "" {
				filePaths = append(filePaths, fp.Value)
			}
		}
	}
	sourceRef := strings.Join(filePaths, "\n")

	title := vuln.CVEID
	desc := vuln.CVESummary
	descriptions := []hdf.Description{
		{Label: "default", Data: desc},
	}

	req := hdf.EvaluatedRequirement{
		ID:           vuln.CVEID,
		Title:        &title,
		Impact:       impact,
		Tags:         tags,
		Descriptions: descriptions,
		Results:      results,
	}

	if sourceRef != "" {
		req.SourceLocation = &hdf.SourceLocation{
			Ref: &sourceRef,
		}
	}

	return req
}

// buildSCAResult creates an HDF RequirementResult from an SCA component finding.
func buildSCAResult(comp Component, firstBuildDate string) hdf.RequirementResult {
	codeDesc := formatSCACodeDesc(comp)

	startTime := parseVeracodeTimestamp(firstBuildDate)
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}

	return hdf.RequirementResult{
		Status:    hdf.Failed,
		CodeDesc:  codeDesc,
		StartTime: startTime,
	}
}

// formatDesc extracts text from Desc paragraphs.
func formatDesc(desc Desc) string {
	var parts []string
	for _, p := range desc.Para {
		if p.Text != "" {
			parts = append(parts, p.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// formatRecommendations extracts text from Recommendations paragraphs and bullet items.
func formatRecommendations(rec Recommendations) string {
	var parts []string
	for _, p := range rec.Para {
		if p.Text != "" {
			parts = append(parts, p.Text)
		}
		for _, b := range p.BulletItems {
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
	}
	return strings.Join(parts, "\n")
}

// formatCWEData formats CWE entries with their category metadata for the cweid tag.
func formatCWEData(cwes []CWE) string {
	var parts []string
	for _, c := range cwes {
		entry := fmt.Sprintf("CWE-%s: %s", c.CWEID, c.CWEName)

		categories := []struct{ name, val string }{
			{"pcrirelated", c.PCIRelated},
			{"owasp", c.OWASP},
			{"sans", c.SANS},
			{"certc", c.CERTC},
			{"certcpp", c.CERTCPP},
			{"certjava", c.CERTJava},
			{"owaspmobile", c.OWASPMobile},
		}
		for _, cat := range categories {
			if cat.val != "" {
				entry += fmt.Sprintf("%s: %s\n", cat.name, cat.val)
			}
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, "\n")
}

// formatCWEDesc formats CWE entries with description text for the cweDescription tag.
func formatCWEDesc(cwes []CWE) string {
	var parts []string
	for _, c := range cwes {
		desc := fmt.Sprintf("CWE-%s: %s Description: %s; ", c.CWEID, c.CWEName, c.Description.Text.Text)
		parts = append(parts, desc)
	}
	return strings.Join(parts, "\n")
}

// formatFlawCodeDesc formats a static analysis flaw as a human-readable code description.
func formatFlawCodeDesc(flaw Flaw) string {
	if flaw.SourceFilePath == "" {
		return fmt.Sprintf("Issue ID: %s", flaw.IssueID)
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("Sourcefile Path: %s", flaw.SourceFilePath))

	fields := []struct{ title, value string }{
		{"Line Number", flaw.Line},
		{"Affect Policy Compliance", flaw.AffectsPolicyCompliance},
		{"Remediation Effort", flaw.RemediationEffort},
		{"Exploit level", flaw.ExploitLevel},
		{"Issue ID", flaw.IssueID},
		{"Module", flaw.Module},
		{"Type", flaw.Type},
		{"CWE ID", flaw.CWEID},
		{"Date First Occurence", flaw.DateFirstOccurrence},
		{"CIA Impact", flaw.CIAImpact},
		{"Description", flaw.Description},
		{"Source File", flaw.SourceFile},
		{"Scope", flaw.Scope},
		{"PCI Related", flaw.PCIRelated},
		{"Function Prototype", flaw.FunctionPrototype},
		{"Function Relative Location", flaw.FunctionRelativeLocation},
	}

	for _, f := range fields {
		if f.value != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.title, f.value))
		}
	}

	return strings.Join(parts, "\n")
}

// formatSCACodeDesc formats an SCA component finding as a code description.
func formatSCACodeDesc(comp Component) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("component_id: %s", comp.ComponentID))

	fields := []struct{ title, value string }{
		{"sha1", comp.SHA1},
		{"file_name", comp.FileName},
		{"max_cvss_score", comp.MaxCVSSScore},
		{"version", comp.Version},
		{"library", comp.Library},
		{"library_id", comp.LibraryID},
		{"vendor", comp.Vendor},
		{"description", comp.Description},
		{"added_date", comp.AddedDate},
		{"component_affects_policy_compliance", comp.ComponentAffectsPolicyCompliance},
	}

	for _, f := range fields {
		if f.value != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.title, f.value))
		}
	}

	// Add file paths
	for _, fp := range comp.FilePaths.FilePath {
		if fp.Value != "" {
			parts = append(parts, fmt.Sprintf("file_path: %s", fp.Value))
		}
	}

	return strings.Join(parts, "\n")
}

// formatSourceLocation collects source file paths from CWE flaws.
func formatSourceLocation(cwes []CWE) string {
	var files []string
	for _, c := range cwes {
		for _, flaw := range c.StaticFlaws.Flaws {
			if flaw.SourceFile != "" {
				files = append(files, flaw.SourceFile)
			}
		}
	}
	return strings.Join(files, "\n")
}

// parseVeracodeTimestamp parses Veracode's timestamp format.
// Veracode uses "2021-12-29 22:16:36 UTC".
func parseVeracodeTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	// Veracode format: "2021-12-29 22:16:36 UTC"
	layouts := []string{
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}

	// Fall back to shared parser
	return shared.ParseTimestamp(s)
}

// cweNISTControls wraps the cwe.NISTControls function for use in this package.
// This is kept for reference — actual mapping is done via shared.MapCWEToNIST.
var _ = cwe.NISTControls
