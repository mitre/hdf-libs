package xccdf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
	"github.com/mitre/hdf-mappings/go/cci"
	hdf "github.com/mitre/hdf-schema"
)

// XML namespace constants
const (
	xccdf12NS = "http://checklists.nist.gov/xccdf/1.2"
	xccdf11NS = "http://checklists.nist.gov/xccdf/1.1"
	arfNS     = "http://scap.nist.gov/schema/asset-reporting-format/1.1"
	coreNS    = "http://scap.nist.gov/schema/reporting-core/1.1"
	aiNS      = "http://scap.nist.gov/schema/asset-identification/1.1"
	dsNS      = "http://scap.nist.gov/schema/scap/source/1.2"
)

// isXccdfNS returns true if the namespace is either XCCDF 1.1 or 1.2.
func isXccdfNS(ns string) bool {
	return ns == xccdf12NS || ns == xccdf11NS
}

// ---------------------------------------------------------------------------
// XCCDF XML structs (namespace-agnostic for 1.1/1.2 compatibility)
// ---------------------------------------------------------------------------
// Namespace prefixes are intentionally omitted from XCCDF element tags so that
// Go's encoding/xml matches both 1.1 and 1.2 namespaces. XCCDF element names
// (Benchmark, Group, Rule, TestResult, etc.) are unique within the schema,
// so there is no collision risk.

// Benchmark is the root element of an XCCDF document.
type Benchmark struct {
	XMLName     xml.Name   `xml:"Benchmark"`
	ID          string     `xml:"id,attr"`
	Status      string     `xml:"status"`
	Title       string     `xml:"title"`
	Description string     `xml:"description"`
	Version     string     `xml:"version"`
	Platforms   []Platform `xml:"platform"`
	Groups      []Group    `xml:"Group"`
	Rules       []Rule     `xml:"Rule"`
	TestResult  TestResult `xml:"TestResult"`
}

// Platform represents an XCCDF platform element.
type Platform struct {
	IDRef string `xml:"idref,attr"`
}

// Group represents an XCCDF Group containing a single Rule.
type Group struct {
	ID    string `xml:"id,attr"`
	Title string `xml:"title"`
	Rule  Rule   `xml:"Rule"`
}

// Rule represents an XCCDF Rule within a Group or top-level Benchmark.
type Rule struct {
	ID          string  `xml:"id,attr"`
	Selected    string  `xml:"selected,attr"`
	Severity    string  `xml:"severity,attr"`
	Weight      string  `xml:"weight,attr"`
	Version     string  `xml:"version"`
	Title       string  `xml:"title"`
	Description string  `xml:"description"`
	Fixtext     Fixtext `xml:"fixtext"`
	Idents      []Ident `xml:"ident"`
	Check       Check   `xml:"check"`
}

// Fixtext represents an XCCDF fixtext element with optional fixref attribute.
type Fixtext struct {
	Text   string `xml:",chardata"`
	Fixref string `xml:"fixref,attr"`
}

// Ident represents an XCCDF ident element (CCI, CCE, etc.).
type Ident struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

// Check represents an XCCDF check element.
type Check struct {
	System       string `xml:"system,attr"`
	CheckContent string `xml:"check-content"`
}

// TestResult represents the XCCDF TestResult element containing scan results.
type TestResult struct {
	ID              string       `xml:"id,attr"`
	StartTime       string       `xml:"start-time,attr"`
	EndTime         string       `xml:"end-time,attr"`
	TestSystem      string       `xml:"test-system,attr"`
	Title           string       `xml:"title"`
	Target          string       `xml:"target"`
	TargetAddresses []string     `xml:"target-address"`
	TargetFacts     TargetFacts  `xml:"target-facts"`
	RuleResults     []RuleResult `xml:"rule-result"`
	Score           Score        `xml:"score"`
}

// TargetFacts holds key-value facts about the scan target.
type TargetFacts struct {
	Facts []Fact `xml:"fact"`
}

// Fact represents a single target fact.
type Fact struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// RuleResult represents the result of evaluating a single rule.
type RuleResult struct {
	IDRef    string  `xml:"idref,attr"`
	Time     string  `xml:"time,attr"`
	Severity string  `xml:"severity,attr"`
	Version  string  `xml:"version,attr"`
	Weight   string  `xml:"weight,attr"`
	Result   string  `xml:"result"`
	Idents   []Ident `xml:"ident"`
	Check    Check   `xml:"check"`
}

// Score represents the XCCDF score element.
type Score struct {
	System  string `xml:"system,attr"`
	Maximum string `xml:"maximum,attr"`
	Value   string `xml:",chardata"`
}

// ---------------------------------------------------------------------------
// ARF 1.1 XML structs
// ---------------------------------------------------------------------------
// ARF struct tags keep their namespaces because ARF documents contain multiple
// schemas (ARF, SCAP, XCCDF, AI) where element name collisions are possible.

// AssetReportCollection is the root element of an ARF document.
type AssetReportCollection struct {
	XMLName        xml.Name          `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 asset-report-collection"`
	Relationships  ArfRelationships  `xml:"http://scap.nist.gov/schema/reporting-core/1.1 relationships"`
	ReportRequests ArfReportRequests `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 report-requests"`
	Assets         ArfAssets         `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 assets"`
	Reports        ArfReports        `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 reports"`
}

// ArfRelationships contains the core:relationships element.
type ArfRelationships struct {
	Relations []ArfRelationship `xml:"http://scap.nist.gov/schema/reporting-core/1.1 relationship"`
}

// ArfRelationship links reports to assets via type="...isAbout".
type ArfRelationship struct {
	Type    string   `xml:"type,attr"`
	Subject string   `xml:"subject,attr"`
	Refs    []string `xml:"http://scap.nist.gov/schema/reporting-core/1.1 ref"`
}

// ArfReportRequests contains the report-request elements.
type ArfReportRequests struct {
	Requests []ArfReportRequest `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 report-request"`
}

// ArfReportRequest contains the source data-stream-collection with benchmarks.
type ArfReportRequest struct {
	ID      string            `xml:"id,attr"`
	Content ArfRequestContent `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 content"`
}

// ArfRequestContent wraps the data-stream-collection inside a report-request.
type ArfRequestContent struct {
	DataStreamCollection DataStreamCollection `xml:"http://scap.nist.gov/schema/scap/source/1.2 data-stream-collection"`
}

// DataStreamCollection holds SCAP source components.
type DataStreamCollection struct {
	Components []DSComponent `xml:"http://scap.nist.gov/schema/scap/source/1.2 component"`
}

// DSComponent holds a single component that may contain a Benchmark.
// The Benchmark uses namespace-agnostic tag to match both 1.1 and 1.2,
// but within ARF the Benchmark is always XCCDF 1.2.
type DSComponent struct {
	ID        string    `xml:"id,attr"`
	Benchmark Benchmark `xml:"Benchmark"`
}

// ArfAssets contains the asset elements.
type ArfAssets struct {
	Assets []ArfAsset `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 asset"`
}

// ArfAsset represents a single ARF asset with computing device metadata.
type ArfAsset struct {
	ID              string          `xml:"id,attr"`
	ComputingDevice ComputingDevice `xml:"http://scap.nist.gov/schema/asset-identification/1.1 computing-device"`
}

// ComputingDevice holds network identity information about a scanned host.
type ComputingDevice struct {
	Connections ArfConnections `xml:"http://scap.nist.gov/schema/asset-identification/1.1 connections"`
	FQDN        string         `xml:"http://scap.nist.gov/schema/asset-identification/1.1 fqdn"`
	Hostname    string         `xml:"http://scap.nist.gov/schema/asset-identification/1.1 hostname"`
}

// ArfConnections contains the connection elements.
type ArfConnections struct {
	Connections []ArfConnection `xml:"http://scap.nist.gov/schema/asset-identification/1.1 connection"`
}

// ArfConnection holds an IP address or MAC address.
type ArfConnection struct {
	IPAddress  ArfIPAddress `xml:"http://scap.nist.gov/schema/asset-identification/1.1 ip-address"`
	MACAddress string       `xml:"http://scap.nist.gov/schema/asset-identification/1.1 mac-address"`
}

// ArfIPAddress holds either an IPv4 or IPv6 address.
type ArfIPAddress struct {
	IPv4 string `xml:"http://scap.nist.gov/schema/asset-identification/1.1 ip-v4"`
	IPv6 string `xml:"http://scap.nist.gov/schema/asset-identification/1.1 ip-v6"`
}

// ArfReports contains the report elements.
type ArfReports struct {
	Reports []ArfReport `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 report"`
}

// ArfReport wraps either an XCCDF TestResult or OVAL results.
type ArfReport struct {
	ID      string           `xml:"id,attr"`
	Content ArfReportContent `xml:"http://scap.nist.gov/schema/asset-reporting-format/1.1 content"`
}

// ArfReportContent holds the report payload. Only TestResult is populated
// for XCCDF reports; OVAL reports leave TestResult empty.
// Uses namespace-agnostic tag to match TestResult from both XCCDF 1.1 and 1.2.
type ArfReportContent struct {
	TestResult TestResult `xml:"TestResult"`
}

// ---------------------------------------------------------------------------
// Severity and status mappings
// ---------------------------------------------------------------------------

// severityToImpact was formerly a local map; now uses hdfutil.SeverityToImpact.
// XCCDF defines three severity levels (high, medium, low) which are all
// covered by the standard mapping. Default for unknown severity is 0.5.

// resultStatusMapping maps XCCDF result strings to HDF ResultStatus values.
var resultStatusMapping = map[string]hdf.ResultStatus{
	"pass":          hdf.Passed,
	"fail":          hdf.Failed,
	"error":         hdf.Error,
	"unknown":       hdf.Error,
	"notapplicable": hdf.NotApplicable,
	"notchecked":    hdf.NotReviewed,
	"notselected":   hdf.NotReviewed,
	"informational": hdf.NotReviewed,
	"fixed":         hdf.Passed,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ConvertXccdfResultsToHDF converts XCCDF (1.1 or 1.2) results or ARF 1.1
// XML to HDF Results format. The input must contain TestResult elements.
// For benchmark-only documents (no TestResult), use ConvertXccdfBenchmarkToHDF.
func ConvertXccdfResultsToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, fmt.Errorf("xccdf: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	rootLocal, rootSpace := peekRootElement(input)
	switch {
	case rootLocal == "Benchmark" && isXccdfNS(rootSpace):
		return convertBenchmarkResultsToHDF(input, converterVersion, resultsChecksum)
	case rootLocal == "asset-report-collection" && rootSpace == arfNS:
		return convertArfToHDF(input, converterVersion, resultsChecksum)
	default:
		return nil, fmt.Errorf("input is not an XCCDF or ARF document")
	}
}

// ConvertXccdfBenchmarkToHDF converts an XCCDF benchmark document (no TestResult)
// to HDF Baseline format. Supports both XCCDF 1.1 and 1.2 namespaces.
func ConvertXccdfBenchmarkToHDF(input []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, fmt.Errorf("xccdf: %w", err)
	}

	rootLocal, rootSpace := peekRootElement(input)
	if rootLocal != "Benchmark" || !isXccdfNS(rootSpace) {
		return nil, fmt.Errorf("input is not an XCCDF Benchmark document")
	}

	var benchmark Benchmark
	if err := xml.Unmarshal(input, &benchmark); err != nil {
		return nil, fmt.Errorf("failed to parse XCCDF XML: %w", err)
	}

	if benchmark.TestResult.ID != "" {
		return nil, fmt.Errorf("input contains TestResult elements — this is a results document, not a benchmark. Use 'xccdf-results' or 'xccdf' instead")
	}

	return convertBenchmarkToBaseline(&benchmark, input, converterVersion)
}

// ConvertXccdfToHDF auto-detects whether the input is an XCCDF benchmark or
// results document (or ARF), and returns the appropriate JSON output.
// Returns (json, "baseline"|"results", error).
func ConvertXccdfToHDF(input []byte, converterVersion string) ([]byte, string, error) {
	if len(input) == 0 {
		return nil, "", fmt.Errorf("empty input")
	}
	if err := shared.ValidateXMLInput(input, 0); err != nil {
		return nil, "", fmt.Errorf("xccdf: %w", err)
	}

	rootLocal, rootSpace := peekRootElement(input)

	switch {
	case rootLocal == "asset-report-collection" && rootSpace == arfNS:
		result, err := ConvertXccdfResultsToHDF(input, converterVersion)
		if err != nil {
			return nil, "", err
		}
		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("failed to serialize HDF output: %w", err)
		}
		return out, "results", nil

	case rootLocal == "Benchmark" && isXccdfNS(rootSpace):
		var benchmark Benchmark
		if err := xml.Unmarshal(input, &benchmark); err != nil {
			return nil, "", fmt.Errorf("failed to parse XCCDF XML: %w", err)
		}

		if benchmark.TestResult.ID != "" {
			// Has TestResult -> results
			result, err := ConvertXccdfResultsToHDF(input, converterVersion)
			if err != nil {
				return nil, "", err
			}
			out, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return nil, "", fmt.Errorf("failed to serialize HDF output: %w", err)
			}
			return out, "results", nil
		}

		// No TestResult -> baseline
		baseline, err := convertBenchmarkToBaseline(&benchmark, input, converterVersion)
		if err != nil {
			return nil, "", err
		}
		out, err := json.MarshalIndent(baseline, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("failed to serialize HDF output: %w", err)
		}
		return out, "baseline", nil

	default:
		return nil, "", fmt.Errorf("input is not an XCCDF or ARF document")
	}
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

// peekRootElement reads the first XML start element from input and returns
// its local name and namespace. Returns empty strings on any parse error.
func peekRootElement(input []byte) (local, space string) {
	decoder := xml.NewDecoder(bytes.NewReader(input))
	for {
		tok, err := decoder.Token()
		if err != nil {
			return "", ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Local, se.Name.Space
		}
	}
}

// ---------------------------------------------------------------------------
// XCCDF Benchmark results conversion (existing path)
// ---------------------------------------------------------------------------

func convertBenchmarkResultsToHDF(input []byte, converterVersion string, resultsChecksum *hdf.Checksum) (*hdf.HDFResults, error) {
	var benchmark Benchmark
	if err := xml.Unmarshal(input, &benchmark); err != nil {
		return nil, fmt.Errorf("failed to parse XCCDF XML: %w", err)
	}

	if benchmark.TestResult.ID == "" {
		return nil, fmt.Errorf("input has no TestResult elements — this is a benchmark. Use 'xccdf-benchmark' or 'xccdf' instead")
	}

	ruleMap := buildRuleMap(&benchmark)
	startTime, duration := calculateTiming(&benchmark.TestResult)

	limitedRuleResults := shared.LimitSliceWithWarning(benchmark.TestResult.RuleResults, 0, "rule result")
	var requirements []hdf.EvaluatedRequirement
	for i := range limitedRuleResults {
		rr := &limitedRuleResults[i]
		rule := ruleMap[rr.IDRef]
		req := convertRuleResult(rr, rule)
		requirements = append(requirements, req)
	}

	baselineName := benchmark.Title
	if baselineName == "" {
		baselineName = benchmark.ID
	}
	status := "loaded"
	baseline := hdf.EvaluatedBaseline{
		Name:            baselineName,
		Title:           hdfutil.Ptr(baselineName),
		Version:         hdfutil.Ptr(benchmark.Version),
		Status:          &status,
		Summary:         hdfutil.Ptr(hdfutil.StripHTML(benchmark.Description)),
		ResultsChecksum: resultsChecksum,
		Requirements:    requirements,
	}

	target := buildTarget(&benchmark.TestResult)

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "hdf-converters",
		ConverterVersion: converterVersion,
		ToolName:         "XCCDF",
		ToolFormat:       "XCCDF",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       []hdf.Component{target},
		Timestamp:        &startTime,
		Statistics: &hdf.Statistics{
			Duration: &duration,
		},
	}), nil
}

// ---------------------------------------------------------------------------
// Benchmark-to-Baseline conversion
// ---------------------------------------------------------------------------

func convertBenchmarkToBaseline(benchmark *Benchmark, input []byte, converterVersion string) (*hdf.HDFBaseline, error) {
	integrity := shared.InputIntegrity(input)

	var requirements []hdf.BaselineRequirement
	var groups []hdf.RequirementGroup

	for i := range benchmark.Groups {
		group := &benchmark.Groups[i]
		rule := &group.Rule
		if rule.ID == "" {
			continue
		}
		req := convertRuleToBaselineRequirement(rule, group)
		requirements = append(requirements, req)
		groups = append(groups, hdf.RequirementGroup{
			ID:           group.ID,
			Title:        hdfutil.Ptr(group.Title),
			Requirements: []string{req.ID},
		})
	}

	for i := range benchmark.Rules {
		rule := &benchmark.Rules[i]
		if rule.ID == "" {
			continue
		}
		req := convertRuleToBaselineRequirement(rule, nil)
		requirements = append(requirements, req)
	}

	baselineName := kebabCase(benchmark.ID)
	status := "loaded"

	baseline := &hdf.HDFBaseline{
		Name:         baselineName,
		Title:        hdfutil.Ptr(benchmark.Title),
		Version:      hdfutil.Ptr(benchmark.Version),
		Status:       &status,
		Summary:      hdfutil.Ptr(hdfutil.StripHTML(benchmark.Description)),
		Integrity:    integrity,
		Requirements: requirements,
		Groups:       groups,
		Generator: &hdf.Generator{
			Name:    "hdf-converters",
			Version: converterVersion,
		},
	}

	return baseline, nil
}

// convertRuleToBaselineRequirement converts a single XCCDF Rule into an HDF
// BaselineRequirement for benchmark-to-baseline conversion.
func convertRuleToBaselineRequirement(rule *Rule, group *Group) hdf.BaselineRequirement {
	id := extractRuleID(rule.ID)
	if id == "" {
		id = rule.Version
	}

	severity := strings.ToLower(rule.Severity)
	impact := hdfutil.SeverityToImpact(severity, 0.5)

	descriptions := buildBaselineDescriptions(rule)
	tags := buildBaselineTags(rule, group)

	var severityPtr *hdf.Severity
	if rule.Severity != "" {
		s := hdf.Severity(strings.ToLower(rule.Severity))
		severityPtr = &s
	}

	return hdf.BaselineRequirement{
		ID:           id,
		Title:        hdfutil.Ptr(rule.Title),
		Impact:       impact,
		Severity:     severityPtr,
		Descriptions: descriptions,
		Tags:         tags,
	}
}

// buildBaselineDescriptions creates HDF Description entries for a baseline requirement.
func buildBaselineDescriptions(rule *Rule) []hdf.Description {
	var descriptions []hdf.Description

	if rule.Description != "" {
		descText := extractVulnDiscussion(rule.Description)
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  hdfutil.StripHTML(descText),
		})
	} else {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  "",
		})
	}

	if rule.Check.CheckContent != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "check",
			Data:  hdfutil.StripHTML(rule.Check.CheckContent),
		})
	}

	if rule.Fixtext.Text != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  hdfutil.StripHTML(rule.Fixtext.Text),
		})
	}

	return descriptions
}

// buildBaselineTags constructs the tags map for a baseline requirement.
func buildBaselineTags(rule *Rule, group *Group) map[string]interface{} {
	tags := make(map[string]interface{})

	var cciIDs []string
	for _, ident := range rule.Idents {
		if isCCIIdent(ident) {
			cciIDs = append(cciIDs, ident.Value)
		}
	}
	cciIDs = dedup(cciIDs)

	if len(cciIDs) > 0 {
		tags["cci"] = cciIDs
		tags["nist"] = cci.CCIToNIST(cciIDs)
	} else {
		tags["nist"] = []string{}
	}

	// STIG-specific tags
	tags["rid"] = rule.ID
	tags["stig_id"] = rule.Version
	if rule.Severity != "" {
		tags["severity"] = strings.ToLower(rule.Severity)
	}
	if rule.Check.System != "" {
		tags["check_id"] = rule.Check.System
	}
	if rule.Fixtext.Fixref != "" {
		tags["fix_id"] = rule.Fixtext.Fixref
	}
	if group != nil {
		tags["gid"] = group.ID
		tags["gtitle"] = group.Title
	}

	return tags
}

// kebabCase converts a string like "MS_Windows_Server_2022_STIG" to
// "ms-windows-server-2022-stig".
func kebabCase(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "_", "-"))
}

// extractRuleID extracts the vulnerability ID from an XCCDF Rule ID.
// Handles two formats:
//   - Bare: "SV-254238r991589_rule" → "SV-254238"
//   - Qualified: "xccdf_mil.disa.stig_rule_SV-204393r603261_rule" → "SV-204393"
//
// The revision suffix (e.g. "r991589_rule") is stripped by splitting on the
// first lowercase 'r' after the SV- digits. Non-SV IDs are returned unchanged.
func extractRuleID(ruleID string) string {
	if ruleID == "" {
		return ""
	}

	// Check for embedded SV- in qualified XCCDF IDs (e.g. "xccdf_..._SV-12345r...")
	svIdx := strings.Index(strings.ToUpper(ruleID), "SV-")
	if svIdx < 0 {
		return ruleID
	}

	// Extract from "SV-" onward
	svPart := "SV-" + ruleID[svIdx+3:]

	// Strip revision suffix: split on first lowercase 'r' after digits
	digits := svPart[3:] // everything after "SV-"
	for i, ch := range digits {
		if ch == 'r' && i > 0 {
			return "SV-" + digits[:i]
		}
	}
	return svPart
}

// ---------------------------------------------------------------------------
// ARF conversion
// ---------------------------------------------------------------------------

func convertArfToHDF(input []byte, converterVersion string, resultsChecksum *hdf.Checksum) (*hdf.HDFResults, error) {
	var arc AssetReportCollection
	if err := xml.Unmarshal(input, &arc); err != nil {
		return nil, fmt.Errorf("failed to parse ARF XML: %w", err)
	}

	// Find the Benchmark from data-stream-collection components
	benchmark := findBenchmarkInARF(&arc)

	// Build rule map from Benchmark (if found)
	var ruleMap map[string]*Rule
	if benchmark != nil {
		ruleMap = buildRuleMap(benchmark)
	} else {
		ruleMap = make(map[string]*Rule)
	}

	// Build asset metadata map: asset ID -> ArfAsset
	assetMap := make(map[string]*ArfAsset)
	for i := range arc.Assets.Assets {
		asset := &arc.Assets.Assets[i]
		assetMap[asset.ID] = asset
	}

	// Build relationship map: report ID -> asset IDs (isAbout relationships)
	reportToAssets := buildReportAssetMap(&arc.Relationships)

	// Process each report, collecting baselines and targets
	var baselines []hdf.EvaluatedBaseline
	var targets []hdf.Component
	var firstTimestamp time.Time
	var totalDuration float64

	for i := range arc.Reports.Reports {
		report := &arc.Reports.Reports[i]

		// Skip non-XCCDF reports (e.g. OVAL)
		if report.Content.TestResult.ID == "" {
			continue
		}

		tr := &report.Content.TestResult
		startTime, duration := calculateTiming(tr)

		if firstTimestamp.IsZero() {
			firstTimestamp = startTime
		}
		totalDuration += duration

		// Convert rule-results
		limitedARFRuleResults := shared.LimitSliceWithWarning(tr.RuleResults, 0, "rule result")
		var requirements []hdf.EvaluatedRequirement
		for j := range limitedARFRuleResults {
			rr := &limitedARFRuleResults[j]
			rule := ruleMap[rr.IDRef]
			req := convertRuleResult(rr, rule)
			requirements = append(requirements, req)
		}

		// Baseline name from Benchmark title
		baselineName := ""
		if benchmark != nil {
			baselineName = benchmark.Title
			if baselineName == "" {
				baselineName = benchmark.ID
			}
		}
		if baselineName == "" {
			baselineName = tr.Title
			if baselineName == "" {
				baselineName = tr.ID
			}
		}

		status := "loaded"
		baseline := hdf.EvaluatedBaseline{
			Name:            baselineName,
			Title:           hdfutil.Ptr(baselineName),
			Status:          &status,
			ResultsChecksum: resultsChecksum,
			Requirements:    requirements,
		}
		if benchmark != nil {
			baseline.Version = hdfutil.Ptr(benchmark.Version)
			baseline.Summary = hdfutil.Ptr(hdfutil.StripHTML(benchmark.Description))
		}
		baselines = append(baselines, baseline)

		// Build target from TestResult, then enrich with ARF asset metadata
		target := buildTarget(tr)
		if assetIDs, ok := reportToAssets[report.ID]; ok {
			for _, assetID := range assetIDs {
				if asset, found := assetMap[assetID]; found {
					enrichTargetWithAsset(&target, asset)
				}
			}
		}
		targets = append(targets, target)
	}

	if len(baselines) == 0 {
		return nil, fmt.Errorf("ARF document contains no XCCDF TestResult reports")
	}

	if firstTimestamp.IsZero() {
		firstTimestamp = time.Now()
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "hdf-converters",
		ConverterVersion: converterVersion,
		ToolName:         "ARF",
		ToolFormat:       "ARF",
		Baselines:        baselines,
		Components:       targets,
		Timestamp:        &firstTimestamp,
		Statistics: &hdf.Statistics{
			Duration: &totalDuration,
		},
	}), nil
}

// findBenchmarkInARF locates the XCCDF Benchmark embedded in the ARF
// data-stream-collection components. Returns nil if no Benchmark is found.
func findBenchmarkInARF(arc *AssetReportCollection) *Benchmark {
	for i := range arc.ReportRequests.Requests {
		dsc := &arc.ReportRequests.Requests[i].Content.DataStreamCollection
		for j := range dsc.Components {
			comp := &dsc.Components[j]
			if comp.Benchmark.ID != "" {
				return &comp.Benchmark
			}
		}
	}
	return nil
}

// buildReportAssetMap extracts "isAbout" relationships linking report IDs
// to asset IDs.
func buildReportAssetMap(rels *ArfRelationships) map[string][]string {
	result := make(map[string][]string)
	for _, rel := range rels.Relations {
		if strings.Contains(rel.Type, "isAbout") {
			result[rel.Subject] = append(result[rel.Subject], rel.Refs...)
		}
	}
	return result
}

// enrichTargetWithAsset adds ARF asset metadata (FQDN, hostname, MAC, IP)
// to an HDF Target.
func enrichTargetWithAsset(target *hdf.Component, asset *ArfAsset) {
	cd := &asset.ComputingDevice

	if cd.FQDN != "" {
		target.FQDN = hdfutil.Ptr(cd.FQDN)
	}

	// Extract first non-loopback MAC address
	for _, conn := range cd.Connections.Connections {
		mac := conn.MACAddress
		if mac != "" && mac != "00:00:00:00:00:00" {
			target.MACAddress = hdfutil.Ptr(mac)
			break
		}
	}

	// If target has no IP yet, try ARF asset connections
	if target.IPAddress == nil {
		for _, conn := range cd.Connections.Connections {
			if conn.IPAddress.IPv4 != "" {
				target.IPAddress = hdfutil.Ptr(conn.IPAddress.IPv4)
				break
			}
			if conn.IPAddress.IPv6 != "" {
				target.IPAddress = hdfutil.Ptr(conn.IPAddress.IPv6)
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Shared helpers (used by both Benchmark and ARF paths)
// ---------------------------------------------------------------------------

// buildRuleMap builds a lookup from rule ID to Rule definition, checking
// both Group/Rule and top-level Rules.
func buildRuleMap(benchmark *Benchmark) map[string]*Rule {
	ruleMap := make(map[string]*Rule)
	for i := range benchmark.Groups {
		rule := &benchmark.Groups[i].Rule
		if rule.ID != "" {
			ruleMap[rule.ID] = rule
		}
	}
	for i := range benchmark.Rules {
		rule := &benchmark.Rules[i]
		if rule.ID != "" {
			ruleMap[rule.ID] = rule
		}
	}
	return ruleMap
}

// calculateTiming computes the start time and duration in seconds from the
// TestResult start-time and end-time attributes.
func calculateTiming(tr *TestResult) (time.Time, float64) {
	startTime := hdfutil.ParseTimestamp(tr.StartTime)
	endTime := hdfutil.ParseTimestamp(tr.EndTime)

	if startTime.IsZero() {
		startTime = time.Now()
	}

	var duration float64
	if !endTime.IsZero() && !startTime.IsZero() {
		duration = endTime.Sub(startTime).Seconds()
		if duration < 0 {
			duration = 0
		}
	}

	return startTime, duration
}

// convertRuleResult converts a single XCCDF rule-result into an HDF
// EvaluatedRequirement, enriching it with the Rule definition if available.
func convertRuleResult(rr *RuleResult, rule *Rule) hdf.EvaluatedRequirement {
	id := determineID(rr, rule)
	title := determineTitle(rr, rule)
	impact := determineImpact(rr, rule)
	descriptions := buildDescriptions(rule)
	tags := buildTags(rr, rule)
	results := []hdf.RequirementResult{buildResult(rr)}

	return hdf.EvaluatedRequirement{
		ID:           id,
		Title:        hdfutil.Ptr(title),
		Descriptions: descriptions,
		Impact:       impact,
		Tags:         tags,
		Results:      results,
	}
}

// determineID returns the requirement ID. Prefers the Rule ID extracted
// as a vulnerability ID (e.g. "SV-254238" from "SV-254238r991589_rule"),
// falling back to the rule-result idref.
func determineID(rr *RuleResult, rule *Rule) string {
	if rule != nil && rule.ID != "" {
		return extractRuleID(rule.ID)
	}
	return rr.IDRef
}

// determineTitle returns the human-readable title from the Rule definition,
// or the idref if no Rule is available.
func determineTitle(rr *RuleResult, rule *Rule) string {
	if rule != nil && rule.Title != "" {
		return rule.Title
	}
	return rr.IDRef
}

// determineImpact maps the severity to a numeric impact. Checks the
// rule-result severity first, then the Rule severity.
func determineImpact(rr *RuleResult, rule *Rule) float64 {
	severity := strings.ToLower(rr.Severity)
	if severity == "" && rule != nil {
		severity = strings.ToLower(rule.Severity)
	}
	return hdfutil.SeverityToImpact(severity, 0.5)
}

// buildDescriptions creates HDF Description entries from the Rule definition.
func buildDescriptions(rule *Rule) []hdf.Description {
	var descriptions []hdf.Description

	if rule != nil && rule.Description != "" {
		descText := extractVulnDiscussion(rule.Description)
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  hdfutil.StripHTML(descText),
		})
	} else {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  "",
		})
	}

	if rule != nil && rule.Fixtext.Text != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  hdfutil.StripHTML(rule.Fixtext.Text),
		})
	}

	return descriptions
}

// extractVulnDiscussion extracts the text content from a <VulnDiscussion>
// XML element embedded in the description string. Returns the full string
// if no VulnDiscussion element is found.
func extractVulnDiscussion(desc string) string {
	const openTag = "<VulnDiscussion>"
	const closeTag = "</VulnDiscussion>"

	startIdx := strings.Index(desc, openTag)
	if startIdx == -1 {
		return desc
	}
	startIdx += len(openTag)

	endIdx := strings.Index(desc[startIdx:], closeTag)
	if endIdx == -1 {
		return desc
	}

	return desc[startIdx : startIdx+endIdx]
}

// buildTags constructs the tags map from CCI idents found in the rule-result
// and rule definition.
func buildTags(rr *RuleResult, rule *Rule) map[string]interface{} {
	tags := make(map[string]interface{})

	var cciIDs []string
	allIdents := collectIdents(rr, rule)

	for _, ident := range allIdents {
		if isCCIIdent(ident) {
			cciIDs = append(cciIDs, ident.Value)
		}
	}

	cciIDs = dedup(cciIDs)

	if len(cciIDs) > 0 {
		tags["cci"] = cciIDs
		tags["nist"] = cci.CCIToNIST(cciIDs)
	} else {
		tags["nist"] = []string{}
	}

	return tags
}

// collectIdents gathers idents from both the rule-result and the rule
// definition. The rule-result idents take priority since they come from
// the actual evaluation.
func collectIdents(rr *RuleResult, rule *Rule) []Ident {
	var idents []Ident
	if rr != nil {
		idents = append(idents, rr.Idents...)
	}
	if rule != nil {
		idents = append(idents, rule.Idents...)
	}
	return idents
}

// isCCIIdent checks whether an Ident's system attribute indicates a CCI.
func isCCIIdent(ident Ident) bool {
	return strings.Contains(strings.ToLower(ident.System), "cci")
}

// dedup returns a deduplicated copy of a string slice, preserving order.
func dedup(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// buildResult converts a rule-result into an HDF RequirementResult.
func buildResult(rr *RuleResult) hdf.RequirementResult {
	status := mapResultStatus(rr.Result)

	startTime := hdfutil.ParseTimestamp(rr.Time)
	if startTime.IsZero() {
		startTime = time.Now()
	}

	return hdf.RequirementResult{
		Status:    status,
		CodeDesc:  fmt.Sprintf("XCCDF rule %s", rr.IDRef),
		StartTime: startTime,
	}
}

// mapResultStatus maps an XCCDF result string to an HDF ResultStatus.
func mapResultStatus(result string) hdf.ResultStatus {
	normalized := strings.ToLower(strings.TrimSpace(result))
	if status, ok := resultStatusMapping[normalized]; ok {
		return status
	}
	return hdf.Error
}

// buildTarget constructs an HDF Target from the TestResult metadata.
func buildTarget(tr *TestResult) hdf.Component {
	target := hdf.Component{
		Name: tr.Target,
		Type: hdf.Host,
	}

	// Use the first target-address as the IP address
	if len(tr.TargetAddresses) > 0 {
		target.IPAddress = hdfutil.Ptr(tr.TargetAddresses[0])
	}

	return target
}
