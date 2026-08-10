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
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
	return hdfutil.SeverityToImpactWithAliases(severity, veracodeAliases, 0.1)
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
	chunk := len(r.buf)
	if chunk > len(p)/utf8.UTFMax {
		chunk = len(p) / utf8.UTFMax
	}
	if chunk == 0 {
		chunk = 1
	}
	n, err := r.r.Read(r.buf[:chunk])
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

	// Merge all requirements into one baseline. Pre-allocate to avoid
	// aliasing cweRequirements' backing array.
	allRequirements := make([]hdf.EvaluatedRequirement, 0, len(cweRequirements)+len(cveRequirements))
	allRequirements = append(allRequirements, cweRequirements...)
	allRequirements = append(allRequirements, cveRequirements...)

	targetName := report.AppName
	if targetName == "" {
		targetName = "Veracode Application"
	}

	if len(allRequirements) == 0 {
		allRequirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"veracode-no-findings",
				fmt.Sprintf("Veracode scanned %s and reported zero findings.", targetName),
				time.Now().UTC(),
			),
		}
	}

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

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "veracode-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Veracode",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{Name: targetName, Type: hdf.Application},
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

	cweDescStr := formatCWEDesc(cat.CWEs)

	extras := map[string]interface{}{}
	if cweDescStr != "" {
		extras["cweDescription"] = cweDescStr
	}

	// Veracode cross-references each CWE to external standards catalogs (OWASP,
	// SANS/CWE Top 25, CERT C/C++/Java, OWASP Mobile). Each becomes a discrete
	// tag carrying the category's distinct referenced entries; absent catalogs
	// are omitted (NOT-IN-SOURCE).
	for _, s := range cweStandardTags {
		if v := collectCWEStandard(cat.CWEs, s.get); len(v) > 0 {
			extras[s.key] = v
		}
	}

	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	// First-class CWE identifiers ("CWE-NN"). The category cweid attributes are
	// bare numbers; prefix them to match the schema's CWE-N convention.
	cweList := make([]string, 0, len(cweIDs))
	for _, id := range cweIDs {
		cweList = append(cweList, "CWE-"+id)
	}

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

	// Carry each flaw's remediation_status (e.g. "New", "Fixed", "Cannot Fix").
	// Descriptions are requirement-level while the field is per-flaw, so the
	// distinct values across the category's flaws are collected into one entry.
	if remStatus := formatRemediationStatus(cat.CWEs); remStatus != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "remediation_status",
			Data:  remStatus,
		})
	}

	// Collect all flaws from all CWEs under this category. Alongside each result
	// synthesize its source-context locus for the requirement-level code string.
	var results []hdf.RequirementResult
	var codeLines []string
	for _, c := range cat.CWEs {
		limited := shared.LimitSliceWithWarning(c.StaticFlaws.Flaws, 0, "flaw")
		for _, flaw := range limited {
			result := buildFlawResult(flaw, firstBuildDate)
			results = append(results, result)
			if line := synthesizeFlawCode(flaw); line != "" {
				codeLines = append(codeLines, line)
			}
		}
	}

	// Build source location from flaw source files
	sourceRef := formatSourceLocation(cat.CWEs)
	sourceLine := firstFlawLine(cat.CWEs)

	title := cat.CategoryName
	req := hdf.EvaluatedRequirement{
		ID:                 cat.CategoryID,
		Title:              &title,
		Impact:             impact,
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}

	if len(cweList) > 0 {
		req.Cwe = cweList
	}

	if sourceRef != "" {
		req.SourceLocation = &hdf.SourceLocation{
			Ref:  &sourceRef,
			Line: sourceLine,
		}
	}

	// Static findings carry no raw snippet; the code-locus (function prototype at
	// source-file:line) is the richest source context Veracode provides. Leave
	// code unset when no flaw carries either (NOT-IN-SOURCE).
	if len(codeLines) > 0 {
		code := strings.Join(codeLines, "\n")
		req.Code = &code
	}

	return req
}

// synthesizeFlawCode renders a static flaw's source-context locus from its
// function prototype and source-file position. Returns "" when the flaw carries
// neither a prototype nor a source location (the NOT-IN-SOURCE case).
func synthesizeFlawCode(flaw Flaw) string {
	locus := flaw.SourceFilePath + flaw.SourceFile
	if locus != "" && flaw.Line != "" {
		locus += ":" + flaw.Line
	}
	switch {
	case flaw.FunctionPrototype != "" && locus != "":
		return flaw.FunctionPrototype + " at " + locus
	case flaw.FunctionPrototype != "":
		return flaw.FunctionPrototype
	default:
		return locus
	}
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
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, nil)

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
		ID:                 vuln.CVEID,
		Title:              &title,
		Impact:             impact,
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}

	if cvss := buildVeracodeCvss(vuln, components); len(cvss) > 0 {
		req.Cvss = cvss
	}

	// CVE is already the requirement.id, so no interim tags.cve is emitted; the
	// CWE moves to the first-class cwe[] (already in "CWE-NN" form on SCA vulns).
	if vuln.CWEID != "" {
		req.Cwe = []string{vuln.CWEID}
	}

	if sourceRef != "" {
		req.SourceLocation = &hdf.SourceLocation{
			Ref: &sourceRef,
		}
	}

	// SCA vulnerabilities have no source snippet or function prototype; the richest
	// faithful representation is the vulnerability/component entry serialized as
	// indented JSON (the ionchannel/nessus pattern).
	code := buildSCACode(vuln, components)
	req.Code = &code

	return req
}

// buildVeracodeCvss assembles the structured CVSS entry for an SCA CVE. Veracode
// reports a bare numeric base score (no vector, no version), so the version
// defaults to 3.1 via the shared helper. When the vulnerability itself carries
// no cvss_score, the first affected component's max_cvss_score is used as a
// fallback. A missing or non-numeric score yields no entry.
func buildVeracodeCvss(vuln Vulnerability, components []Component) []hdf.Cvss {
	scoreStr := vuln.CVSSScore
	if scoreStr == "" {
		for _, comp := range components {
			if comp.MaxCVSSScore != "" {
				scoreStr = comp.MaxCVSSScore
				break
			}
		}
	}
	if scoreStr == "" {
		return nil
	}
	score, err := strconv.ParseFloat(scoreStr, 64)
	if err != nil {
		return nil
	}
	return []hdf.Cvss{shared.BuildCvss(shared.CvssInput{
		Version:   shared.CvssVersionFromString(""),
		BaseScore: &score,
	})}
}

// scaCodeComponent is the JSON shape of an affected component embedded in a CVE
// requirement's code. Field order is load-bearing: it must match the TypeScript
// twin's object-literal insertion order for byte-identical output.
type scaCodeComponent struct {
	ComponentID  string   `json:"component_id"`
	FileName     string   `json:"file_name"`
	SHA1         string   `json:"sha1"`
	Version      string   `json:"version"`
	Library      string   `json:"library"`
	LibraryID    string   `json:"library_id"`
	Vendor       string   `json:"vendor"`
	Description  string   `json:"description"`
	MaxCVSSScore string   `json:"max_cvss_score"`
	AddedDate    string   `json:"added_date"`
	FilePaths    []string `json:"file_paths"`
}

// scaCode is the JSON shape serialized into a CVE requirement's code. Field order
// must match the TypeScript twin.
type scaCode struct {
	CVEID          string             `json:"cve_id"`
	CVSSScore      string             `json:"cvss_score"`
	Severity       string             `json:"severity"`
	CWEID          string             `json:"cwe_id"`
	FirstFoundDate string             `json:"first_found_date"`
	CVESummary     string             `json:"cve_summary"`
	SeverityDesc   string             `json:"severity_desc"`
	Components     []scaCodeComponent `json:"components"`
}

// buildSCACode serializes a CVE and its affected components as indented JSON.
// HTML escaping is off and the trailing newline is trimmed so the bytes match
// the TypeScript twin's JSON.stringify(entry, null, 2).
func buildSCACode(vuln Vulnerability, components []Component) string {
	entry := scaCode{
		CVEID:          vuln.CVEID,
		CVSSScore:      vuln.CVSSScore,
		Severity:       vuln.Severity,
		CWEID:          vuln.CWEID,
		FirstFoundDate: vuln.FirstFoundDate,
		CVESummary:     vuln.CVESummary,
		SeverityDesc:   vuln.SeverityDesc,
		Components:     make([]scaCodeComponent, 0, len(components)),
	}
	for _, comp := range components {
		filePaths := make([]string, 0, len(comp.FilePaths.FilePath))
		for _, fp := range comp.FilePaths.FilePath {
			filePaths = append(filePaths, fp.Value)
		}
		entry.Components = append(entry.Components, scaCodeComponent{
			ComponentID:  comp.ComponentID,
			FileName:     comp.FileName,
			SHA1:         comp.SHA1,
			Version:      comp.Version,
			Library:      comp.Library,
			LibraryID:    comp.LibraryID,
			Vendor:       comp.Vendor,
			Description:  comp.Description,
			MaxCVSSScore: comp.MaxCVSSScore,
			AddedDate:    comp.AddedDate,
			FilePaths:    filePaths,
		})
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entry); err != nil {
		return "{}"
	}
	return strings.TrimSuffix(buf.String(), "\n")
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
		{"Date First Occurence", flaw.DateFirstOccurrence}, //nolint:misspell // label parity with TypeScript converter and stored fixture
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

// cweStandardTags names the standards cross-reference attributes Veracode
// records on each <cwe>, paired with the discrete tag key each maps to. Order is
// deterministic and shared with the TypeScript twin.
var cweStandardTags = []struct {
	key string
	get func(CWE) string
}{
	{"owasp", func(c CWE) string { return c.OWASP }},
	{"sans", func(c CWE) string { return c.SANS }},
	{"certc", func(c CWE) string { return c.CERTC }},
	{"certcpp", func(c CWE) string { return c.CERTCPP }},
	{"certjava", func(c CWE) string { return c.CERTJava }},
	{"owaspmobile", func(c CWE) string { return c.OWASPMobile }},
}

// collectCWEStandard gathers the distinct non-empty values of one standards
// cross-reference attribute across a category's CWEs, in first-appearance order.
// Returns nil when no CWE carries the attribute (the NOT-IN-SOURCE case).
func collectCWEStandard(cwes []CWE, get func(CWE) string) []string {
	var values []string
	seen := map[string]bool{}
	for _, c := range cwes {
		if v := get(c); v != "" && !seen[v] {
			seen[v] = true
			values = append(values, v)
		}
	}
	return values
}

// formatRemediationStatus collects the distinct remediation_status values across
// a category's flaws, in order of first appearance. Returns "" when no flaw
// carries the field (the NOT-IN-SOURCE case).
func formatRemediationStatus(cwes []CWE) string {
	var statuses []string
	seen := map[string]bool{}
	for _, c := range cwes {
		for _, flaw := range c.StaticFlaws.Flaws {
			if flaw.RemediationStatus != "" && !seen[flaw.RemediationStatus] {
				seen[flaw.RemediationStatus] = true
				statuses = append(statuses, flaw.RemediationStatus)
			}
		}
	}
	return strings.Join(statuses, "\n")
}

// firstFlawLine returns the line number of the first flaw carrying a parseable
// numeric line across a category's CWEs — the locus paired with the first source
// file in the joined ref. Returns nil when no flaw carries a numeric line
// (SCA/absent case), so SourceLocation.Line is omitted.
func firstFlawLine(cwes []CWE) *float64 {
	for _, c := range cwes {
		for _, flaw := range c.StaticFlaws.Flaws {
			if flaw.Line == "" {
				continue
			}
			if n, err := strconv.ParseFloat(flaw.Line, 64); err == nil {
				return &n
			}
		}
	}
	return nil
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
			return hdfutil.NormalizeTimestamp(t)
		}
	}

	// Fall back to shared parser
	return hdfutil.ParseTimestamp(s)
}

// cweNISTControls wraps the cwe.NISTControls function for use in this package.
// This is kept for reference — actual mapping is done via shared.MapCWEToNIST.
var _ = cwe.NISTControls
