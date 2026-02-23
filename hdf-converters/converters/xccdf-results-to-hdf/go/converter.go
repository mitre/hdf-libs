package xccdf

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/mitre/hdf-mappings/go/cci"
	hdf "github.com/mitre/hdf-schema"
)

// XML namespace constants
const (
	xccdfNS = "http://checklists.nist.gov/xccdf/1.2"
	arfNS   = "http://scap.nist.gov/schema/asset-reporting-format/1.1"
	coreNS  = "http://scap.nist.gov/schema/reporting-core/1.1"
	aiNS    = "http://scap.nist.gov/schema/asset-identification/1.1"
	dsNS    = "http://scap.nist.gov/schema/scap/source/1.2"
)

// ---------------------------------------------------------------------------
// XCCDF 1.2 XML structs
// ---------------------------------------------------------------------------

// Benchmark is the root element of an XCCDF 1.2 results document.
type Benchmark struct {
	XMLName     xml.Name   `xml:"http://checklists.nist.gov/xccdf/1.2 Benchmark"`
	ID          string     `xml:"id,attr"`
	Status      string     `xml:"http://checklists.nist.gov/xccdf/1.2 status"`
	Title       string     `xml:"http://checklists.nist.gov/xccdf/1.2 title"`
	Description string     `xml:"http://checklists.nist.gov/xccdf/1.2 description"`
	Version     string     `xml:"http://checklists.nist.gov/xccdf/1.2 version"`
	Platform    Platform   `xml:"http://checklists.nist.gov/xccdf/1.2 platform"`
	Groups      []Group    `xml:"http://checklists.nist.gov/xccdf/1.2 Group"`
	Rules       []Rule     `xml:"http://checklists.nist.gov/xccdf/1.2 Rule"`
	TestResult  TestResult `xml:"http://checklists.nist.gov/xccdf/1.2 TestResult"`
}

// Platform represents an XCCDF platform element.
type Platform struct {
	IDRef string `xml:"idref,attr"`
}

// Group represents an XCCDF Group containing a single Rule.
type Group struct {
	ID    string `xml:"id,attr"`
	Title string `xml:"http://checklists.nist.gov/xccdf/1.2 title"`
	Rule  Rule   `xml:"http://checklists.nist.gov/xccdf/1.2 Rule"`
}

// Rule represents an XCCDF Rule within a Group or top-level Benchmark.
type Rule struct {
	ID          string  `xml:"id,attr"`
	Selected    string  `xml:"selected,attr"`
	Severity    string  `xml:"severity,attr"`
	Weight      string  `xml:"weight,attr"`
	Version     string  `xml:"http://checklists.nist.gov/xccdf/1.2 version"`
	Title       string  `xml:"http://checklists.nist.gov/xccdf/1.2 title"`
	Description string  `xml:"http://checklists.nist.gov/xccdf/1.2 description"`
	Fixtext     string  `xml:"http://checklists.nist.gov/xccdf/1.2 fixtext"`
	Idents      []Ident `xml:"http://checklists.nist.gov/xccdf/1.2 ident"`
	Check       Check   `xml:"http://checklists.nist.gov/xccdf/1.2 check"`
}

// Ident represents an XCCDF ident element (CCI, CCE, etc.).
type Ident struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

// Check represents an XCCDF check element.
type Check struct {
	System string `xml:"system,attr"`
}

// TestResult represents the XCCDF TestResult element containing scan results.
type TestResult struct {
	ID              string       `xml:"id,attr"`
	StartTime       string       `xml:"start-time,attr"`
	EndTime         string       `xml:"end-time,attr"`
	TestSystem      string       `xml:"test-system,attr"`
	Title           string       `xml:"http://checklists.nist.gov/xccdf/1.2 title"`
	Target          string       `xml:"http://checklists.nist.gov/xccdf/1.2 target"`
	TargetAddresses []string     `xml:"http://checklists.nist.gov/xccdf/1.2 target-address"`
	TargetFacts     TargetFacts  `xml:"http://checklists.nist.gov/xccdf/1.2 target-facts"`
	RuleResults     []RuleResult `xml:"http://checklists.nist.gov/xccdf/1.2 rule-result"`
	Score           Score        `xml:"http://checklists.nist.gov/xccdf/1.2 score"`
}

// TargetFacts holds key-value facts about the scan target.
type TargetFacts struct {
	Facts []Fact `xml:"http://checklists.nist.gov/xccdf/1.2 fact"`
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
	Result   string  `xml:"http://checklists.nist.gov/xccdf/1.2 result"`
	Idents   []Ident `xml:"http://checklists.nist.gov/xccdf/1.2 ident"`
	Check    Check   `xml:"http://checklists.nist.gov/xccdf/1.2 check"`
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
type DSComponent struct {
	ID        string    `xml:"id,attr"`
	Benchmark Benchmark `xml:"http://checklists.nist.gov/xccdf/1.2 Benchmark"`
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
type ArfReportContent struct {
	TestResult TestResult `xml:"http://checklists.nist.gov/xccdf/1.2 TestResult"`
}

// ---------------------------------------------------------------------------
// Severity and status mappings
// ---------------------------------------------------------------------------

// severityToImpact maps XCCDF severity strings to HDF impact values.
// Audit (2026-02): XCCDF 1.2 defines three severity levels (high, medium, low).
// This mapping matches heimdall2 xccdf-results-mapper.ts IMPACT_MAPPING for
// these three levels. hdf-schema severityToImpact() maps "critical"=1.0 but
// XCCDF does not define a "critical" severity, so that is not relevant here.
// Default for unknown severity is 0.5 (see determineImpact).
var severityToImpact = map[string]float64{
	"high":   0.7,
	"medium": 0.5,
	"low":    0.3,
}

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

// ConvertXccdfResultsToHDF converts XCCDF 1.2 or ARF 1.1 XML to HDF format.
// It detects the input format from the root element and delegates accordingly.
func ConvertXccdfResultsToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	resultsChecksum := shared.InputChecksum(input)

	rootLocal, rootSpace := peekRootElement(input)
	switch {
	case rootLocal == "Benchmark" && rootSpace == xccdfNS:
		return convertBenchmarkToHDF(input, converterVersion, resultsChecksum)
	case rootLocal == "asset-report-collection" && rootSpace == arfNS:
		return convertArfToHDF(input, converterVersion, resultsChecksum)
	default:
		return nil, fmt.Errorf("input is not an XCCDF or ARF document")
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
// XCCDF Benchmark conversion (existing path)
// ---------------------------------------------------------------------------

func convertBenchmarkToHDF(input []byte, converterVersion string, resultsChecksum *hdf.Checksum) (*hdf.HDFResults, error) {
	var benchmark Benchmark
	if err := xml.Unmarshal(input, &benchmark); err != nil {
		return nil, fmt.Errorf("failed to parse XCCDF XML: %w", err)
	}

	if benchmark.XMLName.Local != "Benchmark" || benchmark.XMLName.Space != xccdfNS {
		return nil, fmt.Errorf("input is not an XCCDF 1.2 Benchmark document")
	}

	ruleMap := buildRuleMap(&benchmark)
	startTime, duration := calculateTiming(&benchmark.TestResult)

	var requirements []hdf.EvaluatedRequirement
	for i := range benchmark.TestResult.RuleResults {
		rr := &benchmark.TestResult.RuleResults[i]
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
		Title:           shared.Ptr(baselineName),
		Version:         shared.Ptr(benchmark.Version),
		Status:          &status,
		Summary:         shared.Ptr(shared.StripHTML(benchmark.Description)),
		ResultsChecksum: resultsChecksum,
		Requirements:    requirements,
	}

	target := buildTarget(&benchmark.TestResult)

	dataSourceName := "XCCDF"
	dataSourceFormat := "XCCDF"

	return &hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{baseline},
		Targets:   []hdf.Target{target},
		Statistics: &hdf.Statistics{
			Duration: &duration,
		},
		Generator: &hdf.Generator{
			Name:    "hdf-converters",
			Version: converterVersion,
		},
		DataSource: &hdf.DataSource{
			Name:   &dataSourceName,
			Format: &dataSourceFormat,
		},
		Timestamp: &startTime,
	}, nil
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
	var targets []hdf.Target
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
		var requirements []hdf.EvaluatedRequirement
		for j := range tr.RuleResults {
			rr := &tr.RuleResults[j]
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
			Title:           shared.Ptr(baselineName),
			Status:          &status,
			ResultsChecksum: resultsChecksum,
			Requirements:    requirements,
		}
		if benchmark != nil {
			baseline.Version = shared.Ptr(benchmark.Version)
			baseline.Summary = shared.Ptr(shared.StripHTML(benchmark.Description))
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

	dataSourceName := "ARF"
	dataSourceFormat := "ARF"

	return &hdf.HDFResults{
		Baselines: baselines,
		Targets:   targets,
		Statistics: &hdf.Statistics{
			Duration: &totalDuration,
		},
		Generator: &hdf.Generator{
			Name:    "hdf-converters",
			Version: converterVersion,
		},
		DataSource: &hdf.DataSource{
			Name:   &dataSourceName,
			Format: &dataSourceFormat,
		},
		Timestamp: &firstTimestamp,
	}, nil
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
func enrichTargetWithAsset(target *hdf.Target, asset *ArfAsset) {
	cd := &asset.ComputingDevice

	if cd.FQDN != "" {
		target.FQDN = shared.Ptr(cd.FQDN)
	}

	// Extract first non-loopback MAC address
	for _, conn := range cd.Connections.Connections {
		mac := conn.MACAddress
		if mac != "" && mac != "00:00:00:00:00:00" {
			target.MACAddress = shared.Ptr(mac)
			break
		}
	}

	// If target has no IP yet, try ARF asset connections
	if target.IPAddress == nil {
		for _, conn := range cd.Connections.Connections {
			if conn.IPAddress.IPv4 != "" {
				target.IPAddress = shared.Ptr(conn.IPAddress.IPv4)
				break
			}
			if conn.IPAddress.IPv6 != "" {
				target.IPAddress = shared.Ptr(conn.IPAddress.IPv6)
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
	startTime := shared.ParseTimestamp(tr.StartTime)
	endTime := shared.ParseTimestamp(tr.EndTime)

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
		Title:        shared.Ptr(title),
		Descriptions: descriptions,
		Impact:       impact,
		Tags:         tags,
		Results:      results,
	}
}

// determineID returns the requirement ID. Prefers the Rule version text
// (e.g. "RHEL-07-010030"), falling back to the rule-result idref.
func determineID(rr *RuleResult, rule *Rule) string {
	if rule != nil && rule.Version != "" {
		return rule.Version
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
	if impact, ok := severityToImpact[severity]; ok {
		return impact
	}
	return 0.5
}

// buildDescriptions creates HDF Description entries from the Rule definition.
func buildDescriptions(rule *Rule) []hdf.Description {
	var descriptions []hdf.Description

	if rule != nil && rule.Description != "" {
		descText := extractVulnDiscussion(rule.Description)
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  shared.StripHTML(descText),
		})
	} else {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  "",
		})
	}

	if rule != nil && rule.Fixtext != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "fix",
			Data:  shared.StripHTML(rule.Fixtext),
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

	startTime := shared.ParseTimestamp(rr.Time)
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
func buildTarget(tr *TestResult) hdf.Target {
	target := hdf.Target{
		Name: tr.Target,
		Type: hdf.Host,
	}

	// Use the first target-address as the IP address
	if len(tr.TargetAddresses) > 0 {
		target.IPAddress = shared.Ptr(tr.TargetAddresses[0])
	}

	return target
}
