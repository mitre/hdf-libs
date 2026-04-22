// Package hdftoxccdf converts HDF Results JSON to XCCDF 1.2 Benchmark XML.
package hdftoxccdf

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
)

// ConvertHDFToXCCDF converts HDF Results JSON to XCCDF 1.2 XML.
func ConvertHDFToXCCDF(input []byte, converterVersion string) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "hdf-to-xccdf", 0); err != nil {
		return nil, err
	}

	var hdfData hdf.HDFResults
	if err := json.Unmarshal(input, &hdfData); err != nil {
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
	XMLName    xml.Name         `xml:"Benchmark"`
	XMLNS      string           `xml:"xmlns,attr"`
	ID         string           `xml:"id,attr"`
	Resolved   string           `xml:"resolved,attr"`
	Status     string           `xml:"status"`
	Title      string           `xml:"title"`
	Version    string           `xml:"version"`
	Profiles   []XCCDFProfile   `xml:"Profile,omitempty"`
	Rules      []XCCDFRule      `xml:"Rule"`
	TestResult *XCCDFTestResult `xml:"TestResult,omitempty"`
}

// XCCDFProfile represents an XCCDF Profile element.
type XCCDFProfile struct {
	XMLName xml.Name `xml:"Profile"`
	ID      string   `xml:"id,attr"`
	Title   string   `xml:"title"`
}

// XCCDFRule represents an XCCDF Rule element.
type XCCDFRule struct {
	XMLName     xml.Name     `xml:"Rule"`
	ID          string       `xml:"id,attr"`
	Severity    string       `xml:"severity,attr"`
	Selected    string       `xml:"selected,attr"`
	Title       string       `xml:"title"`
	Description string       `xml:"description,omitempty"`
	Fixtext     string       `xml:"fixtext,omitempty"`
	Idents      []XCCDFIdent `xml:"ident,omitempty"`
	Check       *XCCDFCheck  `xml:"check,omitempty"`
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
	Title         string            `xml:"title"`
	Target        string            `xml:"target"`
	TargetAddress string            `xml:"target-address,omitempty"`
	RuleResults   []XCCDFRuleResult `xml:"rule-result"`
}

// XCCDFRuleResult represents an XCCDF rule-result element.
type XCCDFRuleResult struct {
	XMLName xml.Name    `xml:"rule-result"`
	IDRef   string      `xml:"idref,attr"`
	Time    string      `xml:"time,attr,omitempty"`
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

	// Add profile
	benchmark.Profiles = []XCCDFProfile{
		{
			ID:    sanitizeXCCDFID("xccdf_hdf_profile_" + baseline.Name),
			Title: benchmark.Title,
		},
	}

	// Build rules from requirements
	for _, req := range baseline.Requirements {
		rule := buildRule(req)
		benchmark.Rules = append(benchmark.Rules, rule)
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

	if req.Title != nil {
		rule.Title = *req.Title
	} else {
		rule.Title = req.ID
	}

	// Map descriptions
	rule.Description = findDescription(req.Descriptions, "default")
	rule.Fixtext = findDescription(req.Descriptions, "fix")

	// Map check content
	checkContent := findDescription(req.Descriptions, "check")
	if checkContent != "" {
		rule.Check = &XCCDFCheck{
			System:       "http://oval.mitre.org/XMLSchema/oval-definitions-5",
			CheckContent: checkContent,
		}
	}

	// Map CCI idents from tags
	if req.Tags != nil {
		if cciRaw, ok := req.Tags["cci"]; ok {
			ccis := hdfutil.SafeStringSlice(cciRaw)
			for _, cci := range ccis {
				rule.Idents = append(rule.Idents, XCCDFIdent{
					System: "http://cyber.mil/cci",
					Value:  cci,
				})
			}
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

	// Set timestamps
	if hdfData.Timestamp != nil {
		ts := hdfData.Timestamp.Format(time.RFC3339)
		testResult.StartTime = ts
		testResult.EndTime = ts
	}

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

		for _, result := range req.Results {
			rr := XCCDFRuleResult{
				IDRef:  ruleIDRef,
				Result: hdfStatusToXCCDF(result.Status),
			}

			rr.Time = result.StartTime.Format(time.RFC3339)

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

	return testResult
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
