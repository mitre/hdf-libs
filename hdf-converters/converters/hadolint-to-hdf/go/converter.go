// Package hadolint converts hadolint Dockerfile linter output to HDF.
//
// hadolint's JSON formatter emits a bare array of flat findings, each carrying
// only code, column, file, level, line and message. One requirement is produced
// per distinct rule code and one result per finding, so a rule that fires on
// several lines keeps every occurrence.
package hadolint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hadolintmap "github.com/mitre/hdf-libs/hdf-mappings/go/v3/hadolint"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const converterName = "hadolint"

// Finding is one entry of hadolint's JSON output. These six fields are the
// whole contract; the formatter emits nothing else, and no run or tool
// metadata accompanies them.
type Finding struct {
	Code    string `json:"code"`
	Column  int    `json:"column"`
	File    string `json:"file"`
	Level   string `json:"level"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// codeFor renders the finding for requirement.code. The struct is marshalled
// rather than the source bytes echoed, so the two language twins agree
// regardless of how the source laid the object out; hadolint's six fields are
// the whole contract, so nothing is lost. HTML escaping is off because Go
// escapes < and > where JavaScript does not, and rule messages contain both.
func codeFor(f Finding) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return ""
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// levelImpact is hadolint's severity vocabulary as its JSON writer spells it.
// An ignored rule serializes as the empty string, and anything unrecognized
// scores zero rather than guessing.
var levelImpact = map[string]float64{
	"error":   0.7,
	"warning": 0.5,
	"info":    0.3,
	"style":   0.1,
	"":        0.0,
}

func impactFor(level string) float64 {
	return hdfutil.SeverityToImpactWithAliases(level, levelImpact, 0.0)
}

// controlsFor resolves a rule's NIST controls and CCIs, falling back to the
// static-analysis controls when the rule is unmapped. A mapped rule can still
// translate to nothing — the table is authored at Rev 5 and SR-4 has no Rev 4
// equivalent — so an empty result takes the fallback too rather than leaving
// the finding with an empty nist tag.
func controlsFor(ruleID string) (nist, ccis []string) {
	if m, ok := hadolintmap.Lookup(ruleID); ok && len(m.NIST) > 0 {
		return m.NIST, cci.NISTToCCI(m.NIST)
	}
	fallback := append([]string(nil), shared.DefaultStaticAnalysisNIST...)
	return fallback, cci.NISTToCCI(fallback)
}

func codeDescFor(f Finding) string {
	return fmt.Sprintf("File: %s | Line: %d | Column: %d", f.File, f.Line, f.Column)
}

func findingToResult(f Finding, scanTime time.Time) hdf.RequirementResult {
	message := f.Message
	return hdf.RequirementResult{
		Status:    hdf.Failed,
		CodeDesc:  codeDescFor(f),
		Message:   &message,
		StartTime: scanTime,
	}
}

// groupFindings returns the distinct rule codes in first-seen order alongside
// their findings, so output ordering is deterministic without sorting.
func groupFindings(findings []Finding) ([]string, map[string][]Finding) {
	order := make([]string, 0, len(findings))
	groups := make(map[string][]Finding, len(findings))
	for _, f := range findings {
		if _, seen := groups[f.Code]; !seen {
			order = append(order, f.Code)
		}
		groups[f.Code] = append(groups[f.Code], f)
	}
	return order, groups
}

func buildRequirement(ruleID string, group []Finding, scanTime time.Time) hdf.EvaluatedRequirement {
	first := group[0]
	nist, ccis := controlsFor(ruleID)
	tags := shared.BuildNISTCCITags(nist, ccis)

	results := make([]hdf.RequirementResult, 0, len(group))
	for _, f := range group {
		results = append(results, findingToResult(f, scanTime))
	}

	// The message is the rule's own text for hadolint's DL rules, but is
	// parameterized for shellcheck's SC rules. Each result carries its own, so
	// the title naming the first occurrence loses nothing.
	title := first.Message
	req := hdf.EvaluatedRequirement{
		ID:                 ruleID,
		Title:              &title,
		Descriptions:       []hdf.Description{{Label: "default", Data: first.Message}},
		Impact:             impactFor(first.Level),
		Tags:               tags,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
	if url := ruleReferenceURL(ruleID); url != "" {
		req.Refs = []hdf.Reference{{URL: hdfutil.Ptr(url)}}
	}
	if code := codeFor(first); code != "" {
		req.Code = &code
	}
	if first.File != "" {
		location := &hdf.SourceLocation{Ref: hdfutil.Ptr(first.File)}
		if first.Line > 0 {
			location.Line = hdfutil.Ptr(float64(first.Line))
		}
		req.SourceLocation = location
	}
	if controlType := shared.DeriveControlTypeFromTags(nist); controlType != nil {
		req.ControlType = controlType
	}
	return req
}

// componentsFor names each distinct scanned file. hadolint accepts several
// Dockerfiles in one run and tags every finding with the file it came from.
func componentsFor(findings []Finding) []hdf.Component {
	seen := make(map[string]bool, len(findings))
	var components []hdf.Component
	for _, f := range findings {
		if f.File == "" || seen[f.File] {
			continue
		}
		seen[f.File] = true
		components = append(components, hdf.Component{Name: f.File, Type: hdf.Repository})
	}
	return components
}

func baselineTitle(components []hdf.Component) string {
	switch len(components) {
	case 0:
		return "Hadolint Scan"
	case 1:
		return "Hadolint Scan of " + components[0].Name
	default:
		return fmt.Sprintf("Hadolint Scan of %d files", len(components))
	}
}

// parseReport applies the input guards and decodes the findings array. isSarif
// reports a SARIF-shaped input, which the converter delegates: hadolint can
// emit SARIF as well as JSON, though its SARIF collapses info and style to
// "note", so the JSON path carries strictly more severity detail.
// ConvertHadolintToHDF and ExpectedRequirementCount share this so they accept
// and reject exactly the same inputs.
func parseReportOrSarif(input []byte) (findings []Finding, isSarif bool, err error) {
	if len(input) == 0 {
		return nil, false, fmt.Errorf("%s: empty input", converterName)
	}
	if sizeErr := shared.ValidateJSONSize(input, converterName, 0); sizeErr != nil {
		return nil, false, fmt.Errorf("%s: %w", converterName, sizeErr)
	}
	if result := registry.DetectConverter(input); result != nil && result.Fingerprint.ID == "sarif-to-hdf" {
		return nil, true, nil
	}
	if err := json.Unmarshal(input, &findings); err != nil {
		return nil, false, fmt.Errorf("%s: input is not a hadolint findings array: %w", converterName, err)
	}
	// encoding/json accepts the literal null for a slice and leaves it nil,
	// which would otherwise read as a clean scan; decoding [] yields a non-nil
	// empty slice, so a genuinely clean report is unaffected.
	if findings == nil {
		return nil, false, fmt.Errorf("%s: input is not a hadolint findings array; a null list is a malformed report, not a clean one", converterName)
	}
	// Capping here rather than in the conversion keeps the expected-count
	// relation reading the same findings the conversion emits.
	return shared.LimitSliceWithWarning(findings, 0, "finding"), false, nil
}

// parseReport is parseReportOrSarif for callers that have already ruled out
// SARIF, and is what the fidelity tests read the finding count from.
func parseReport(input []byte) ([]Finding, error) {
	findings, isSarif, err := parseReportOrSarif(input)
	if err != nil {
		return nil, err
	}
	if isSarif {
		return nil, fmt.Errorf("%s: input is SARIF, not a hadolint findings array", converterName)
	}
	return findings, nil
}

// ConvertHadolintToHDF converts hadolint JSON output to HDF results. It
// performs no I/O: each requirement links its rule's documentation rather than
// embedding it.
func ConvertHadolintToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	findings, isSarif, err := parseReportOrSarif(input)
	if err != nil {
		return nil, err
	}
	if isSarif {
		return sarif.ConvertSarifToHDF(input, converterVersion)
	}

	resultsChecksum := shared.InputChecksum(input)

	// hadolint reports no scan time, so the conversion time stands in for both
	// the document timestamp and every result's start time.
	scanTime := time.Now().UTC()
	components := componentsFor(findings)

	order, groups := groupFindings(findings)
	requirements := make([]hdf.EvaluatedRequirement, 0, len(order))
	for _, ruleID := range order {
		requirements = append(requirements, buildRequirement(ruleID, groups[ruleID], scanTime))
	}
	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"hadolint-no-findings",
				"hadolint scanned the Dockerfile and reported zero findings.",
				scanTime,
			),
		}
	}

	title := baselineTitle(components)
	baseline := hdf.EvaluatedBaseline{
		Name:            "Hadolint Scan",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "hadolint-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         converterName,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       components,
		Timestamp:        &scanTime,
	}), nil
}

// ExpectedRequirementCount states how many requirements the input must convert
// to: one per distinct rule code, or one no-findings requirement for a clean
// report. SARIF-shaped input defers to the SARIF converter's own relation, as
// the conversion does.
func ExpectedRequirementCount(input []byte) (int, string, error) {
	const unit = "distinct hadolint rule codes"
	findings, isSarif, err := parseReportOrSarif(input)
	if err != nil {
		return 0, unit, err
	}
	if isSarif {
		return sarif.ExpectedRequirementCount(input)
	}
	order, _ := groupFindings(findings)
	if len(order) == 0 {
		return 1, unit, nil
	}
	return len(order), unit, nil
}
