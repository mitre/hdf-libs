package netsparker

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/owasp"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
	ExtraInformation   NetsparkerExtraInfoBlock `xml:"extra-information"`
}

// NetsparkerExtraInfoBlock represents the <extra-information> element: a set of
// name/value <info> entries Netsparker/Invicti attaches to some findings.
type NetsparkerExtraInfoBlock struct {
	Info []NetsparkerExtraInfo `xml:"info"`
}

// NetsparkerExtraInfo represents a single <info> entry within <extra-information>.
type NetsparkerExtraInfo struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// NetsparkerClassification represents the <classification> element.
type NetsparkerClassification struct {
	OWASP    string         `xml:"owasp"`
	WASC     string         `xml:"wasc"`
	CWE      string         `xml:"cwe"`
	CAPEC    string         `xml:"capec"`
	PCI32    string         `xml:"pci32"`
	ISO27001 string         `xml:"iso27001"`
	CVSS     NetsparkerCVSS `xml:"cvss"`
	CVSS31   NetsparkerCVSS `xml:"cvss31"`
}

// NetsparkerCVSS represents a <cvss> or <cvss31> block: a vector plus a set of
// scored metrics (Base / Temporal / Environmental).
type NetsparkerCVSS struct {
	Vector string                `xml:"vector"`
	Scores []NetsparkerCVSSScore `xml:"score"`
}

// NetsparkerCVSSScore represents a single <score> entry within a CVSS block.
type NetsparkerCVSSScore struct {
	Type     string `xml:"type"`
	Value    string `xml:"value"`
	Severity string `xml:"severity"`
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

// formatExtraInformation renders the <extra-information> info entries as
// "name=>value" pairs joined by ", ", mirroring the converter's Classification
// line style. Returns "" when there are no entries.
func formatExtraInformation(info []NetsparkerExtraInfo) string {
	if len(info) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(info))
	for i := range info {
		pairs = append(pairs, fmt.Sprintf("%s=>%s", info[i].Name, info[i].Value))
	}
	return strings.Join(pairs, ", ")
}

func formatControlDesc(vuln *NetsparkerVuln) string {
	parts := []string{}
	if vuln.Description != "" {
		parts = append(parts, hdfutil.StripHTML(vuln.Description))
	}
	if vuln.ExploitationSkills != "" {
		parts = append(parts, fmt.Sprintf("Exploitation-skills: %s", vuln.ExploitationSkills))
	}
	if extra := formatExtraInformation(vuln.ExtraInformation.Info); extra != "" {
		parts = append(parts, fmt.Sprintf("Extra-information: %s", extra))
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
		return hdfutil.NormalizeTimestamp(t)
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

// baseScoreFromScores returns the parsed Base-metric value from a CVSS block's
// scores, or nil when there is no Base score or its value does not parse.
func baseScoreFromScores(scores []NetsparkerCVSSScore) *float64 {
	for i := range scores {
		if strings.EqualFold(scores[i].Type, "Base") {
			v, err := strconv.ParseFloat(strings.TrimSpace(scores[i].Value), 64)
			if err != nil {
				return nil
			}
			return &v
		}
	}
	return nil
}

// buildNetsparkerCvss assembles the structured cvss[] from the <cvss> (3.0) and
// <cvss31> (3.1) classification blocks. Each block carrying a vector or a Base
// score becomes one entry; the schema Version derives from the vector prefix.
func buildNetsparkerCvss(c NetsparkerClassification) []hdf.Cvss {
	var out []hdf.Cvss
	for _, block := range []NetsparkerCVSS{c.CVSS, c.CVSS31} {
		score := baseScoreFromScores(block.Scores)
		if block.Vector == "" && score == nil {
			continue
		}
		out = append(out, shared.BuildCvss(shared.CvssInput{
			Version:    shared.CvssVersionFromVector(block.Vector),
			BaseScore:  score,
			BaseVector: block.Vector,
		}))
	}
	return out
}

// hrefPattern extracts the URL from each anchor tag in Netsparker's
// <external-references> HTML blob (single- or double-quoted href).
var hrefPattern = regexp.MustCompile(`href=['"]([^'"]+)['"]`)

// buildRefs turns Netsparker's <external-references> HTML anchor blob into one
// hdf.Reference per external URL. Returns nil when the field is empty or carries
// no links, so refs[] is omitted entirely.
func buildRefs(externalReferences string) []hdf.Reference {
	matches := hrefPattern.FindAllStringSubmatch(externalReferences, -1)
	refs := make([]hdf.Reference, 0, len(matches))
	for _, m := range matches {
		// Reference.url is schema-constrained to format "uri"; only emit
		// absolute hrefs (a scheme is present), skipping empty/relative/fragment.
		url := strings.TrimSpace(m[1])
		if !strings.Contains(url, "://") {
			continue
		}
		u := url
		refs = append(refs, hdf.Reference{URL: &u})
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
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
	// Source-native categorization strings Netsparker/Invicti carries in
	// <classification>. Each is single-valued; omit the tag when empty.
	if capec := vuln.Classification.CAPEC; capec != "" {
		extras["capec"] = capec
	}
	if wasc := vuln.Classification.WASC; wasc != "" {
		extras["wasc"] = wasc
	}
	if iso := vuln.Classification.ISO27001; iso != "" {
		extras["iso27001"] = iso
	}
	if pci := vuln.Classification.PCI32; pci != "" {
		extras["pci32"] = pci
	}

	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)
	shared.MarkUnratedSeverity(tags, vuln.Severity)

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

	req := hdf.EvaluatedRequirement{
		ID:                 vuln.LookupID,
		Title:              &title,
		Impact:             impact,
		Tags:               tags,
		Descriptions:       descriptions,
		Results:            []hdf.RequirementResult{result},
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}

	// requirement.code = the raw HTTP request that triggered the finding — the
	// natural CODE-tab fill for a DAST tool. Leave unset when absent.
	if vuln.HTTPRequest.Content != "" {
		req.Code = hdfutil.Ptr(vuln.HTTPRequest.Content)
	}

	if cvss := buildNetsparkerCvss(vuln.Classification); len(cvss) > 0 {
		req.Cvss = cvss
	}

	// requirement.refs = external reference links Netsparker carries in the
	// <external-references> HTML blob. Left unset when the vuln carries none.
	req.Refs = buildRefs(vuln.ExternalReferences)

	return req
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

	targetName := netsparkerData.Target.URL
	if targetName == "" {
		targetName = "Unknown"
	}

	// Build one requirement per vulnerability
	requirements := make([]hdf.EvaluatedRequirement, len(limitedVulns))
	for i := range limitedVulns {
		requirements[i] = buildRequirement(&limitedVulns[i], netsparkerData.Target.Initiated)
	}

	if len(requirements) == 0 {
		startTime := parseNetsparkerTimestamp(netsparkerData.Target.Initiated)
		if startTime.IsZero() {
			startTime = time.Now().UTC()
		}
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"netsparker-no-findings",
				fmt.Sprintf("%s scanned %s and reported zero findings.", toolName, targetName),
				startTime,
			),
		}
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

	// Top-level timestamp is the report's `generated` attribute (parsed as UTC).
	// Fall back to now() only when the source omits or malforms it, so a source
	// with `generated` converts deterministically.
	timestamp := parseNetsparkerTimestamp(netsparkerData.Generated)
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "netsparker-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         toolName,
		Timestamp:        &timestamp,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{
			{
				Name: targetName,
				Type: hdf.Application,
			},
		},
	}), nil
}
