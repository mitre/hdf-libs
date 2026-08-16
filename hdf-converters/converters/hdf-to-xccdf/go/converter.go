// Package hdftoxccdf converts HDF Results JSON to XCCDF 1.2 Benchmark XML.
package hdftoxccdf

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertHDFToXCCDF converts HDF Results JSON to XCCDF 1.2 XML.
func ConvertHDFToXCCDF(input []byte, converterVersion string) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "hdf-to-xccdf", 0); err != nil {
		return nil, err
	}

	var hdfData hdf.HDFResults
	if err := shared.DecodeHDF(input, &hdfData); err != nil {
		return nil, fmt.Errorf("invalid HDF JSON: %w", err)
	}

	if hdfData.Baselines == nil {
		return nil, fmt.Errorf("invalid HDF structure: missing baselines field")
	}

	benchmark := buildBenchmark(&hdfData)

	output, err := xml.MarshalIndent(benchmark, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XCCDF XML: %w", err)
	}

	result := append([]byte(xml.Header), output...)
	return result, nil
}

// --- XCCDF 1.2 output structs ---

// XCCDFBenchmark is the root element of an XCCDF 1.2 document.
type XCCDFBenchmark struct {
	XMLName  xml.Name `xml:"Benchmark"`
	XMLNS    string   `xml:"xmlns,attr"`
	ID       string   `xml:"id,attr"`
	Resolved string   `xml:"resolved,attr"`
	Status   string   `xml:"status"`
	Title    string   `xml:"title"`
	// XCCDF benchmarkType orders description after title and before version.
	Description string         `xml:"description,omitempty"`
	Version     string         `xml:"version"`
	Profiles    []XCCDFProfile `xml:"Profile,omitempty"`
	// Rules carrying a Group (gid/gtitle tags) are emitted inside their Group so
	// the reverse importer reconstructs the SSG/STIG hierarchy; ungrouped rules
	// stay flat under the Benchmark.
	Groups     []XCCDFGroup     `xml:"Group,omitempty"`
	Rules      []XCCDFRule      `xml:"Rule,omitempty"`
	TestResult *XCCDFTestResult `xml:"TestResult,omitempty"`
}

// XCCDFGroup represents an XCCDF Group element wrapping one or more Rules.
type XCCDFGroup struct {
	XMLName xml.Name    `xml:"Group"`
	ID      string      `xml:"id,attr"`
	Title   string      `xml:"title,omitempty"`
	Rules   []XCCDFRule `xml:"Rule"`
}

// XCCDFProfile represents an XCCDF Profile element.
type XCCDFProfile struct {
	XMLName xml.Name `xml:"Profile"`
	ID      string   `xml:"id,attr"`
	Title   string   `xml:"title"`
}

// XCCDFRule represents an XCCDF Rule element.
type XCCDFRule struct {
	XMLName  xml.Name `xml:"Rule"`
	ID       string   `xml:"id,attr"`
	Severity string   `xml:"severity,attr"`
	Selected string   `xml:"selected,attr"`
	// XCCDF ruleType orders version before title; carries the STIG ID.
	Version     string           `xml:"version,omitempty"`
	Title       string           `xml:"title"`
	Description string           `xml:"description,omitempty"`
	References  []XCCDFReference `xml:"reference,omitempty"`
	Rationale   string           `xml:"rationale,omitempty"`
	// XCCDF Rule is an ordered sequence: ident precedes fixtext/fix/check.
	Idents  []XCCDFIdent `xml:"ident,omitempty"`
	Fixtext string       `xml:"fixtext,omitempty"`
	Checks  []XCCDFCheck `xml:"check,omitempty"`
}

// XCCDFReference represents an XCCDF reference element (href attr or text).
type XCCDFReference struct {
	XMLName xml.Name `xml:"reference"`
	Href    string   `xml:"href,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// XCCDFIdent represents an XCCDF ident element (e.g. CCI).
type XCCDFIdent struct {
	XMLName xml.Name `xml:"ident"`
	System  string   `xml:"system,attr"`
	Value   string   `xml:",chardata"`
}

// XCCDFCheck represents an XCCDF check element.
type XCCDFCheck struct {
	XMLName      xml.Name `xml:"check"`
	System       string   `xml:"system,attr"`
	CheckContent string   `xml:"check-content,omitempty"`
}

// XCCDFTestResult represents an XCCDF TestResult element.
type XCCDFTestResult struct {
	XMLName       xml.Name          `xml:"TestResult"`
	ID            string            `xml:"id,attr"`
	StartTime     string            `xml:"start-time,attr,omitempty"`
	EndTime       string            `xml:"end-time,attr,omitempty"`
	TestSystem    string            `xml:"test-system,attr,omitempty"`
	Title         string            `xml:"title"`
	Target        string            `xml:"target"`
	TargetAddress string            `xml:"target-address,omitempty"`
	RuleResults   []XCCDFRuleResult `xml:"rule-result"`
	// XCCDF requires at least one score element after the rule-results.
	Score XCCDFScore `xml:"score"`
}

// XCCDFScore represents the required XCCDF TestResult score element.
type XCCDFScore struct {
	XMLName xml.Name `xml:"score"`
	System  string   `xml:"system,attr"`
	Maximum string   `xml:"maximum,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// XCCDFRuleResult represents an XCCDF rule-result element.
type XCCDFRuleResult struct {
	XMLName xml.Name    `xml:"rule-result"`
	IDRef   string      `xml:"idref,attr"`
	Time    string      `xml:"time,attr,omitempty"`
	Version string      `xml:"version,attr,omitempty"`
	Result  string      `xml:"result"`
	Message string      `xml:"message,omitempty"`
	Check   *XCCDFCheck `xml:"check,omitempty"`
}

// --- Mapping functions ---

// impactToSeverity maps HDF impact (0.0-1.0) to XCCDF severity.
func impactToSeverity(impact float64) string {
	switch {
	case impact >= 0.7:
		return "high"
	case impact >= 0.4:
		return "medium"
	case impact >= 0.1:
		return "low"
	default:
		return "info"
	}
}

// hdfStatusToXCCDF maps HDF result status to XCCDF result values.
func hdfStatusToXCCDF(status hdf.ResultStatus) string {
	switch status {
	case hdf.Passed:
		return "pass"
	case hdf.Failed:
		return "fail"
	case hdf.Error:
		return "error"
	case hdf.NotReviewed:
		return "notchecked"
	case hdf.NotApplicable:
		return "notapplicable"
	default:
		return "unknown"
	}
}

// findDescription returns the data for a description with the given label.
func findDescription(descs []hdf.Description, label string) string {
	for _, d := range descs {
		if d.Label == label {
			return d.Data
		}
	}
	return ""
}

// buildBenchmark constructs the XCCDF Benchmark from HDF Results.
func buildBenchmark(hdfData *hdf.HDFResults) *XCCDFBenchmark {
	benchmark := &XCCDFBenchmark{
		XMLNS:    "http://checklists.nist.gov/xccdf/1.2",
		Resolved: "1",
		Status:   "incomplete",
	}

	if len(hdfData.Baselines) == 0 {
		benchmark.ID = "xccdf_hdf_benchmark_exported"
		benchmark.Title = "HDF Export"
		benchmark.Version = "1.0"
		return benchmark
	}

	baseline := hdfData.Baselines[0]

	// Set benchmark metadata from baseline
	benchmark.ID = sanitizeXCCDFID("xccdf_hdf_benchmark_" + baseline.Name)
	if baseline.Title != nil && *baseline.Title != "" {
		benchmark.Title = *baseline.Title
	} else {
		benchmark.Title = baseline.Name
	}
	if baseline.Version != nil {
		benchmark.Version = *baseline.Version
	} else {
		benchmark.Version = "1.0"
	}

	if baseline.Summary != nil {
		benchmark.Description = *baseline.Summary
	}

	// Add profile
	benchmark.Profiles = []XCCDFProfile{
		{
			ID:    sanitizeXCCDFID("xccdf_hdf_profile_" + baseline.Name),
			Title: benchmark.Title,
		},
	}

	// Build rules from requirements, wrapping any rule that carries a gid tag in
	// its XCCDF Group (dedup by gid, preserving first-seen order).
	groupIndex := make(map[string]int)
	for _, req := range baseline.Requirements {
		rule := buildRule(req)
		gid := hdfutil.SafeString(req.Tags["gid"])
		if gid == "" {
			benchmark.Rules = append(benchmark.Rules, rule)
			continue
		}
		idx, ok := groupIndex[gid]
		if !ok {
			idx = len(benchmark.Groups)
			groupIndex[gid] = idx
			benchmark.Groups = append(benchmark.Groups, XCCDFGroup{
				ID:    gid,
				Title: hdfutil.SafeString(req.Tags["gtitle"]),
			})
		}
		benchmark.Groups[idx].Rules = append(benchmark.Groups[idx].Rules, rule)
	}

	// Build TestResult
	benchmark.TestResult = buildTestResult(hdfData, baseline)

	return benchmark
}

// buildRule constructs an XCCDF Rule from an HDF EvaluatedRequirement.
func buildRule(req hdf.EvaluatedRequirement) XCCDFRule {
	ruleID := sanitizeXCCDFID("xccdf_hdf_rule_" + req.ID + "_rule")

	rule := XCCDFRule{
		ID:       ruleID,
		Severity: impactToSeverity(req.Impact),
		Selected: "true",
	}

	if stigID := hdfutil.SafeString(req.Tags["stig_id"]); stigID != "" {
		rule.Version = stigID
	}

	if req.Title != nil {
		rule.Title = *req.Title
	} else {
		rule.Title = req.ID
	}

	// Map descriptions
	rule.Description = findDescription(req.Descriptions, "default")
	rule.Fixtext = findDescription(req.Descriptions, "fix")
	rule.Rationale = findDescription(req.Descriptions, "rationale")

	// References: url/uri -> href attr; plain string ref -> text
	for _, r := range req.Refs {
		switch {
		case r.URL != nil:
			rule.References = append(rule.References, XCCDFReference{Href: *r.URL})
		case r.URI != nil:
			rule.References = append(rule.References, XCCDFReference{Href: *r.URI})
		case r.Ref != nil && r.Ref.String != nil:
			rule.References = append(rule.References, XCCDFReference{Value: *r.Ref.String})
		}
	}

	// Checks: the check-description (OVAL) and the InSpec source code, each its own <check>.
	if checkContent := findDescription(req.Descriptions, "check"); checkContent != "" {
		rule.Checks = append(rule.Checks, XCCDFCheck{
			System:       "http://oval.mitre.org/XMLSchema/oval-definitions-5",
			CheckContent: checkContent,
		})
	}
	if req.Code != nil {
		rule.Checks = append(rule.Checks, XCCDFCheck{
			System:       "http://inspec.io/",
			CheckContent: *req.Code,
		})
	}

	// Idents: CCI, CCE, legacy DISA IDs, and NIST 800-53 controls. Order (cci,
	// cce, legacy, nist) is shared with the TS twin for byte parity; the reverse
	// importer buckets by @system so order does not affect the round-trip.
	if req.Tags != nil {
		for _, cci := range hdfutil.SafeStringSlice(req.Tags["cci"]) {
			rule.Idents = append(rule.Idents, XCCDFIdent{System: "http://cyber.mil/cci", Value: cci})
		}
		if cce := hdfutil.SafeString(req.Tags["cce"]); cce != "" {
			rule.Idents = append(rule.Idents, XCCDFIdent{System: "http://cce.mitre.org", Value: cce})
		}
		for _, legacy := range hdfutil.SafeStringSlice(req.Tags["legacy_id"]) {
			rule.Idents = append(rule.Idents, XCCDFIdent{System: "http://cyber.mil/legacy", Value: legacy})
		}
		for _, n := range hdfutil.SafeStringSlice(req.Tags["nist"]) {
			rule.Idents = append(rule.Idents, XCCDFIdent{System: "https://csrc.nist.gov/projects/risk-management/sp800-53-controls", Value: n})
		}
	}

	return rule
}

// buildTestResult constructs the XCCDF TestResult from HDF data.
func buildTestResult(hdfData *hdf.HDFResults, baseline hdf.EvaluatedBaseline) *XCCDFTestResult {
	testResult := &XCCDFTestResult{
		ID:    "xccdf_hdf_testresult_1",
		Title: "HDF Assessment Results",
	}

	// Set timestamps. end-time carries the scan window: start + statistics.duration
	// so the duration round-trips (the importer derives duration = end − start).
	if hdfData.Timestamp != nil {
		start := hdfData.Timestamp.UTC()
		testResult.StartTime = start.Format(time.RFC3339Nano)
		end := start
		if hdfData.Statistics != nil && hdfData.Statistics.Duration != nil && *hdfData.Statistics.Duration > 0 {
			end = start.Add(time.Duration(*hdfData.Statistics.Duration * float64(time.Second)))
		}
		testResult.EndTime = end.Format(time.RFC3339Nano)
	}

	// @test-system names the scanner via a CPE URI so the importer recovers
	// tool.version from it. Emitted only when the HDF carries a tool identity.
	testResult.TestSystem = toolTestSystem(hdfData.Tool)

	// Set target info
	if len(hdfData.Components) > 0 {
		target := hdfData.Components[0]
		testResult.Target = target.Name
		if target.IPAddress != nil {
			testResult.TargetAddress = *target.IPAddress
		}
	} else {
		testResult.Target = "unknown"
	}

	// Build rule-results from requirement results
	for _, req := range baseline.Requirements {
		ruleIDRef := sanitizeXCCDFID("xccdf_hdf_rule_" + req.ID + "_rule")
		stigID := hdfutil.SafeString(req.Tags["stig_id"])

		// When an override set requirement.effectiveStatus, the emitted result
		// reflects the governing (post-override) status; otherwise each result's
		// own raw status carries through.
		var effective string
		if req.EffectiveStatus != nil {
			effective = hdfStatusToXCCDF(*req.EffectiveStatus)
		}

		for _, result := range req.Results {
			status := effective
			if status == "" {
				status = hdfStatusToXCCDF(result.Status)
			}
			rr := XCCDFRuleResult{
				IDRef:   ruleIDRef,
				Version: stigID,
				Result:  status,
			}

			// RFC3339Nano keeps the sub-second fraction, matching the canonical
			// string the TypeScript converter passes through.
			rr.Time = result.StartTime.Format(time.RFC3339Nano)

			if result.Message != nil && *result.Message != "" {
				rr.Message = *result.Message
			}

			if result.CodeDesc != "" {
				rr.Check = &XCCDFCheck{
					System:       "http://oval.mitre.org/XMLSchema/oval-definitions-5",
					CheckContent: result.CodeDesc,
				}
			}

			testResult.RuleResults = append(testResult.RuleResults, rr)
		}
	}

	// XCCDF requires a score element. Emit the default-model pass percentage
	// over scorable (pass/fail) rule-results.
	passed, scorable := 0, 0
	for _, rr := range testResult.RuleResults {
		switch rr.Result {
		case "pass":
			passed++
			scorable++
		case "fail":
			scorable++
		}
	}
	score := 0.0
	if scorable > 0 {
		score = float64(passed) / float64(scorable) * 100
	}
	testResult.Score = XCCDFScore{
		System:  "urn:xccdf:scoring:default",
		Maximum: "100.000000",
		Value:   fmt.Sprintf("%.6f", score),
	}

	return testResult
}

// toolTestSystem renders the HDF tool identity as the CPE 2.2 URI that XCCDF's
// TestResult/@test-system conventionally carries, so the reverse importer
// recovers tool.version from it (it reads the 4th colon-field). Returns "" when
// no tool version is available, leaving the attribute unset rather than
// fabricating a scanner identity.
func toolTestSystem(tool *hdf.Tool) string {
	if tool == nil || tool.Version == nil || *tool.Version == "" {
		return ""
	}
	name := "tool"
	if tool.Name != nil && *tool.Name != "" {
		name = cpeField(*tool.Name)
	}
	return fmt.Sprintf("cpe:/a:%s:%s:%s", name, name, cpeField(*tool.Version))
}

// cpeField lowercases a value and strips the ':' and whitespace that would
// break CPE 2.2 field parsing.
func cpeField(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Map(func(r rune) rune {
		if r == ':' || r == ' ' {
			return '_'
		}
		return r
	}, s)
}

// sanitizeXCCDFID replaces characters not valid in XCCDF IDs with underscores.
func sanitizeXCCDFID(id string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, id)
}
