package netsparker

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
	"github.com/mitre/hdf-mappings/go/cci"
	"github.com/mitre/hdf-mappings/go/cwe"
	"github.com/mitre/hdf-mappings/go/owasp"
	hdf "github.com/mitre/hdf-schema"
)

// --- XML input structures ---

// NetsparkerXML is a wrapper that handles both <netsparker-enterprise> and
// <invicti-enterprise> root elements. We use xml.Decoder manually rather than
// xml.Unmarshal so we can detect which root element is used.
type NetsparkerXML struct {
	Generated       string           `xml:"generated,attr"`
	Target          NetsparkerTarget `xml:"target"`
	Vulnerabilities struct {
		Vulnerability []NetsparkerVuln `xml:"vulnerability"`
	} `xml:"vulnerabilities"`
}

// NetsparkerTarget represents the <target> element.
type NetsparkerTarget struct {
	ScanID    string `xml:"scan-id"`
	URL       string `xml:"url"`
	Initiated string `xml:"initiated"`
	Duration  string `xml:"duration"`
}

// NetsparkerVuln represents a single <vulnerability> element.
type NetsparkerVuln struct {
	LookupID           string                   `xml:"LookupId"`
	URL                string                   `xml:"url"`
	Type               string                   `xml:"type"`
	Name               string                   `xml:"name"`
	Severity           string                   `xml:"severity"`
	Certainty          string                   `xml:"certainty"`
	Confirmed          string                   `xml:"confirmed"`
	State              string                   `xml:"state"`
	FirstSeenDate      string                   `xml:"FirstSeenDate"`
	LastSeenDate       string                   `xml:"LastSeenDate"`
	Classification     NetsparkerClassification `xml:"classification"`
	HTTPRequest        NetsparkerHTTPRequest    `xml:"http-request"`
	HTTPResponse       NetsparkerHTTPResponse   `xml:"http-response"`
	Description        string                   `xml:"description"`
	Impact             string                   `xml:"impact"`
	RemedialActions    string                   `xml:"remedial-actions"`
	ExploitationSkills string                   `xml:"exploitation-skills"`
	RemedialProcedure  string                   `xml:"remedial-procedure"`
	RemedyReferences   string                   `xml:"remedy-references"`
	ExternalReferences string                   `xml:"external-references"`
	ProofOfConcept     string                   `xml:"proof-of-concept"`
}

// NetsparkerClassification represents the <classification> element.
type NetsparkerClassification struct {
	OWASP    string `xml:"owasp"`
	WASC     string `xml:"wasc"`
	CWE      string `xml:"cwe"`
	CAPEC    string `xml:"capec"`
	ISO27001 string `xml:"iso27001"`
}

// NetsparkerHTTPRequest represents the <http-request> element.
type NetsparkerHTTPRequest struct {
	Method  string `xml:"method"`
	Content string `xml:"content"`
}

// NetsparkerHTTPResponse represents the <http-response> element.
type NetsparkerHTTPResponse struct {
	StatusCode string `xml:"status-code"`
	Duration   string `xml:"duration"`
	Content    string `xml:"content"`
}

// --- Severity to impact mapping ---
// Matches heimdall2 netsparker-mapper.ts IMPACT_MAPPING.
// "best_practice" is Netsparker-specific; standard levels + "information" are
// handled by the shared standard map.

var netsparkerAliases = map[string]float64{
	"best_practice": 0.0,
}

func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, netsparkerAliases, 0.5)
}

// --- Format helpers ---

func formatCodeDesc(request NetsparkerHTTPRequest) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("http-request : %s", request.Content))
	parts = append(parts, fmt.Sprintf("method : %s", request.Method))
	return strings.Join(parts, "\n")
}

func formatMessage(response NetsparkerHTTPResponse) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("http-response : %s", response.Content))
	parts = append(parts, fmt.Sprintf("duration : %s", response.Duration))
	parts = append(parts, fmt.Sprintf("status-code  : %s", response.StatusCode))
	return strings.Join(parts, "\n")
}

func formatControlDesc(vuln *NetsparkerVuln) string {
	parts := []string{}
	if vuln.Description != "" {
		parts = append(parts, hdfutil.StripHTML(vuln.Description))
	}
	if vuln.ExploitationSkills != "" {
		parts = append(parts, fmt.Sprintf("Exploitation-skills: %s", vuln.ExploitationSkills))
	}
	if vuln.Classification.CWE != "" || vuln.Classification.OWASP != "" {
		parts = append(parts, fmt.Sprintf("Classification: cwe=>%s, owasp=>%s", vuln.Classification.CWE, vuln.Classification.OWASP))
	}
	if vuln.Impact != "" {
		parts = append(parts, fmt.Sprintf("Impact: %s", hdfutil.StripHTML(vuln.Impact)))
	}
	if vuln.FirstSeenDate != "" {
		parts = append(parts, fmt.Sprintf("FirstSeenDate: %s", vuln.FirstSeenDate))
	}
	if vuln.LastSeenDate != "" {
		parts = append(parts, fmt.Sprintf("LastSeenDate: %s", vuln.LastSeenDate))
	}
	if vuln.Certainty != "" {
		parts = append(parts, fmt.Sprintf("Certainty: %s", vuln.Certainty))
	}
	if vuln.Type != "" {
		parts = append(parts, fmt.Sprintf("Type: %s", vuln.Type))
	}
	if vuln.Confirmed != "" {
		parts = append(parts, fmt.Sprintf("Confirmed: %s", vuln.Confirmed))
	}
	return strings.Join(parts, "\n")
}

// parseNetsparkerTimestamp parses Netsparker's "MM/DD/YYYY HH:MM PM" format.
// Falls back to hdfutil.ParseTimestamp for other formats.
func parseNetsparkerTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// Netsparker format: "01/02/2006 03:04 PM"
	if t, err := time.Parse("01/02/2006 03:04 PM", s); err == nil {
		return t
	}
	return hdfutil.ParseTimestamp(s)
}

// mapNISTFromCWEAndOWASP performs dual NIST mapping from both CWE and OWASP IDs.
// Returns a deduplicated sorted list of NIST controls, falling back to
// DefaultStaticAnalysisNIST if no mappings are found.
func mapNISTFromCWEAndOWASP(cweID, owaspID string) []string {
	seen := make(map[string]bool)

	// CWE → NIST
	if cweID != "" {
		for _, ctrl := range cwe.NISTControls(cweID) {
			seen[ctrl] = true
		}
	}

	// OWASP → NIST
	if owaspID != "" {
		ctrl := owasp.NISTControl(owaspID)
		if ctrl != "" {
			seen[ctrl] = true
		}
	}

	if len(seen) == 0 {
		return shared.DefaultStaticAnalysisNIST
	}

	result := make([]string, 0, len(seen))
	for ctrl := range seen {
		result = append(result, ctrl)
	}
	sort.Strings(result)
	return result
}

// buildRequirement converts a single vulnerability into an EvaluatedRequirement.
func buildRequirement(vuln *NetsparkerVuln, initiated string) hdf.EvaluatedRequirement {
	cweID := vuln.Classification.CWE
	owaspID := vuln.Classification.OWASP

	nist := mapNISTFromCWEAndOWASP(cweID, owaspID)
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{}
	if cweID != "" {
		extras["cweid"] = cweID
	}
	if owaspID != "" {
		extras["owasp"] = owaspID
	}

	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	// Description
	defaultDesc := formatControlDesc(vuln)
	if defaultDesc == "" {
		defaultDesc = vuln.Name
	}
	descriptions := []hdf.Description{
		{Label: "default", Data: defaultDesc},
	}

	// Check description
	checkParts := []string{}
	if vuln.ExploitationSkills != "" {
		checkParts = append(checkParts, fmt.Sprintf("Exploitation-skills: %s", vuln.ExploitationSkills))
	}
	if vuln.ProofOfConcept != "" {
		checkParts = append(checkParts, fmt.Sprintf("Proof-of-concept: %s", hdfutil.StripHTML(vuln.ProofOfConcept)))
	}
	if len(checkParts) > 0 {
		descriptions = append(descriptions, hdf.Description{
			Label: "check",
			Data:  hdfutil.StripHTML(strings.Join(checkParts, "\n")),
		})
	}

	// Fix description
	fixParts := []string{}
	if vuln.RemedialActions != "" {
		fixParts = append(fixParts, fmt.Sprintf("Remedial-actions: %s", hdfutil.StripHTML(vuln.RemedialActions)))
	}
	if vuln.RemedialProcedure != "" {
		fixParts = append(fixParts, fmt.Sprintf("Remedial-procedure: %s", hdfutil.StripHTML(vuln.RemedialProcedure)))
	}
	if vuln.RemedyReferences != "" {
		fixParts = append(fixParts, fmt.Sprintf("Remedy-references: %s", hdfutil.StripHTML(vuln.RemedyReferences)))
	}
	if len(fixParts) > 0 {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  strings.Join(fixParts, "\n"),
		})
	}

	// Result
	codeDesc := formatCodeDesc(vuln.HTTPRequest)
	message := formatMessage(vuln.HTTPResponse)
	startTime := parseNetsparkerTimestamp(initiated)

	result := hdf.RequirementResult{
		Status:    hdf.Failed,
		CodeDesc:  codeDesc,
		Message:   &message,
		StartTime: startTime,
	}

	impact := getImpact(vuln.Severity)
	title := vuln.Name

	return hdf.EvaluatedRequirement{
		ID:           vuln.LookupID,
		Title:        &title,
		Impact:       impact,
		Tags:         tags,
		Descriptions: descriptions,
		Results:      []hdf.RequirementResult{result},
	}
}

// detectRootElement reads the first start element of the XML to determine
// whether the root is <netsparker-enterprise> or <invicti-enterprise>.
func detectRootElement(input []byte) string {
	decoder := xml.NewDecoder(strings.NewReader(string(input)))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		if se, ok := token.(xml.StartElement); ok {
			return se.Name.Local
		}
	}
}

// ConvertNetsparkerToHDF converts Netsparker/Invicti XML scan results to HDF format.
// Handles both <netsparker-enterprise> and <invicti-enterprise> root elements.
func ConvertNetsparkerToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("netsparker: empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, fmt.Errorf("netsparker: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	// Detect root element to determine tool name
	rootElement := detectRootElement(input)
	isInvicti := strings.HasPrefix(rootElement, "invicti")

	toolName := "Netsparker"
	if isInvicti {
		toolName = "Invicti"
	}

	// Parse XML — we need a wrapper struct that handles either root element.
	// Since encoding/xml requires matching element names, we try invicti first,
	// then netsparker.
	var netsparkerData NetsparkerXML
	if isInvicti {
		type invictiWrapper struct {
			XMLName xml.Name `xml:"invicti-enterprise"`
			NetsparkerXML
		}
		var wrapper invictiWrapper
		if err := xml.Unmarshal(input, &wrapper); err != nil {
			return nil, fmt.Errorf("failed to parse Invicti XML: %w", err)
		}
		netsparkerData = wrapper.NetsparkerXML
	} else {
		type netsparkerWrapper struct {
			XMLName xml.Name `xml:"netsparker-enterprise"`
			NetsparkerXML
		}
		var wrapper netsparkerWrapper
		if err := xml.Unmarshal(input, &wrapper); err != nil {
			return nil, fmt.Errorf("failed to parse Netsparker XML: %w", err)
		}
		netsparkerData = wrapper.NetsparkerXML
	}

	vulns := netsparkerData.Vulnerabilities.Vulnerability
	limitedVulns := shared.LimitSliceWithWarning(vulns, 0, "vulnerability")

	// Build one requirement per vulnerability
	requirements := make([]hdf.EvaluatedRequirement, len(limitedVulns))
	for i := range limitedVulns {
		requirements[i] = buildRequirement(&limitedVulns[i], netsparkerData.Target.Initiated)
	}

	// Build baseline
	title := fmt.Sprintf("%s Enterprise Scan ID: %s URL: %s",
		toolName,
		netsparkerData.Target.ScanID,
		netsparkerData.Target.URL)
	baseline := hdf.EvaluatedBaseline{
		Name:            "Netsparker Scan",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	// Target
	targetName := netsparkerData.Target.URL
	if targetName == "" {
		targetName = "Unknown"
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "netsparker-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         toolName,
		ToolFormat:       "XML",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{
				Name: targetName,
				Type: hdf.CopyrightApplication,
			},
		},
	}), nil
}
