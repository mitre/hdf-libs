// Package semgrep converts native `semgrep scan --json` output to HDF.
//
// Semgrep's SARIF output is delegated to the SARIF converter (see the format
// routing in ConvertSemgrepToHDF); native JSON is converted here because SARIF
// keeps the rule metadata only as untyped prose tags on the rule object and
// drops impact, likelihood, the ASVS control mapping, reference URLs and
// vulnerability_class outright.
package semgrep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	cwemap "github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// semgrepSeverityAliases maps semgrep's native three-level scale onto the
// canonical impact tiers, mirroring the sarif converter's error/warning/note
// aliases. INFO is deliberately 0.3 (an actionable low, semgrep's analogue of
// SARIF "note"), not the canonical 0.0 info tier. Supply-chain severities
// (critical/high/medium/low) resolve through the shared canonical map.
var semgrepSeverityAliases = map[string]float64{
	"error":   0.7,
	"warning": 0.5,
	"info":    0.3,
}

const (
	// defaultImpact treats an unrecognized or absent severity as moderate; the
	// absent case additionally carries the shared unrated marker so consumers
	// can tell a defaulted 0.5 from a genuine medium.
	defaultImpact = 0.5
	// redactedPlaceholder is what semgrep substitutes for fields it withholds
	// from unauthenticated scans.
	redactedPlaceholder = "requires login"
	scanErrorsID        = "semgrep-scan-errors"
	coverageID          = "semgrep-scan-coverage"
)

var cweIDPattern = regexp.MustCompile(`(?i)CWE-(\d+)`)

func isPresent[T ~string](value T) bool {
	return value != "" && string(value) != redactedPlaceholder
}

// extractCweIDs pulls the bare number out of semgrep's prose CWE form,
// "CWE-89: Improper Neutralization of ...".
func extractCweIDs(metadata Metadata) []string {
	ids := make([]string, 0, len(metadata.CWE))
	for _, entry := range metadata.CWE {
		match := cweIDPattern.FindStringSubmatch(entry)
		if match == nil {
			continue
		}
		ids = append(ids, match[1])
	}
	return ids
}

// cweCatalogFor renders the parsed CWE ids in the CWE-N catalog form the
// schema's cwe[] field asks for, deduplicated in source order.
func cweCatalogFor(metadata Metadata) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(metadata.CWE))
	for _, id := range extractCweIDs(metadata) {
		entry := "CWE-" + strings.TrimLeft(id, "0")
		if entry == "CWE-" || seen[entry] {
			continue
		}
		seen[entry] = true
		out = append(out, entry)
	}
	return out
}

// nistControlsFor mirrors the TypeScript lookup. Note the mapping APIs are not
// symmetric: Go's NISTControls returns a slice per CWE while TypeScript's
// getCweNistControl returns the single NIST-ID. They agree on the current
// mapping data, and the shared expected fixtures fail if that ever changes.
func nistControlsFor(metadata Metadata) []string {
	seen := make(map[string]bool)
	controls := make([]string, 0, len(metadata.CWE))
	for _, cweID := range extractCweIDs(metadata) {
		for _, control := range cwemap.NISTControls(cweID) {
			if control == "" || seen[control] {
				continue
			}
			seen[control] = true
			controls = append(controls, control)
		}
	}
	if len(controls) == 0 {
		return append([]string(nil), shared.DefaultStaticAnalysisNIST...)
	}
	return controls
}

func impactFor(result Result) float64 {
	if !isPresent(result.Extra.Severity) {
		return defaultImpact
	}
	return hdfutil.SeverityToImpactWithAliases(string(result.Extra.Severity), semgrepSeverityAliases, defaultImpact)
}

// titleFor derives a readable rule name. Semgrep rule ids are dotted paths
// whose final segment is the rule name; the JSON output carries no
// human-readable title anywhere, unlike its SARIF output.
func titleFor(checkID string) string {
	segments := strings.Split(checkID, ".")
	ruleName := checkID
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i] != "" {
			ruleName = segments[i]
			break
		}
	}
	words := strings.FieldsFunc(ruleName, func(r rune) bool { return r == '-' || r == '_' })
	for i, word := range words {
		if word == "" {
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.Join(words, " ")
}

func codeDescFor(result Result) string {
	path := string(result.Path)
	if path == "" {
		path = "unknown"
	}
	if result.Start.Line == 0 {
		return fmt.Sprintf("Path: %s", path)
	}
	if result.End.Line == 0 || result.End.Line == result.Start.Line {
		return fmt.Sprintf("Path: %s, line %d", path, result.Start.Line)
	}
	return fmt.Sprintf("Path: %s, lines %d-%d", path, result.Start.Line, result.End.Line)
}

// sourceLocationFor points at the first occurrence of the rule; per-occurrence
// locations remain on each result's codeDesc.
func sourceLocationFor(result Result) *hdf.SourceLocation {
	if !isPresent(result.Path) {
		return nil
	}
	location := &hdf.SourceLocation{Ref: hdfutil.Ptr(string(result.Path))}
	if result.Start.Line > 0 {
		location.Line = hdfutil.Ptr(float64(result.Start.Line))
	}
	return location
}

func messageFor(result Result) string {
	parts := make([]string, 0, 2)
	if isPresent(result.Extra.Lines) {
		parts = append(parts, "Matched code:\n"+string(result.Extra.Lines))
	}
	// Fix is replacement text for the matched span, not a standalone
	// instruction -- rendering it bare produces "Suggested fix: False".
	if isPresent(result.Extra.Fix) {
		parts = append(parts, "Suggested fix -- replace the matched code with:\n"+string(result.Extra.Fix))
	}
	return strings.Join(parts, "\n\n")
}

func referencesFor(metadata Metadata) []string {
	candidates := append([]string(nil), metadata.References...)
	candidates = append(candidates, string(metadata.Source), string(metadata.Shortlink), string(metadata.SourceRuleURL))
	if url, ok := metadata.ASVS["control_url"].(string); ok {
		candidates = append(candidates, url)
	}
	seen := make(map[string]bool)
	urls := make([]string, 0, len(candidates))
	for _, url := range candidates {
		if !isPresent(url) || seen[url] {
			continue
		}
		seen[url] = true
		urls = append(urls, url)
	}
	return urls
}

// refsFor emits the deduplicated reference URLs into refs[], their structured
// HDF home.
func refsFor(metadata Metadata) []hdf.Reference {
	urls := referencesFor(metadata)
	if len(urls) == 0 {
		return nil
	}
	refs := make([]hdf.Reference, len(urls))
	for i, url := range urls {
		refs[i] = hdf.Reference{URL: hdfutil.Ptr(url)}
	}
	return refs
}

func tagsFor(metadata Metadata, checkID, severity string) (map[string]any, []string) {
	nist := nistControlsFor(metadata)
	ccis := cci.NISTToCCI(nist)

	tags := map[string]any{"nist": nist, "checkId": checkID}
	if len(ccis) > 0 {
		tags["cci"] = ccis
	}
	if len(metadata.CWE) > 0 {
		tags["cwe"] = []string(metadata.CWE)
	}
	if len(metadata.OWASP) > 0 {
		tags["owasp"] = []string(metadata.OWASP)
	}
	if len(metadata.Subcategory) > 0 {
		tags["subcategory"] = []string(metadata.Subcategory)
	}
	if len(metadata.Technology) > 0 {
		tags["technology"] = []string(metadata.Technology)
	}
	if len(metadata.VulnerabilityClass) > 0 {
		tags["vulnerabilityClass"] = []string(metadata.VulnerabilityClass)
	}
	if isPresent(severity) {
		tags["severity"] = severity
	}
	if isPresent(metadata.Confidence) {
		tags["confidence"] = string(metadata.Confidence)
	}
	if isPresent(metadata.Likelihood) {
		tags["likelihood"] = string(metadata.Likelihood)
	}
	// Renamed: semgrep's metadata.impact rates the severity of the consequence
	// and is not HDF's impact float. Tagging it as "impact" would shadow it.
	if isPresent(metadata.Impact) {
		tags["semgrepImpact"] = string(metadata.Impact)
	}
	if isPresent(metadata.Category) {
		tags["category"] = string(metadata.Category)
	}
	if isPresent(metadata.BanditCode) {
		tags["banditCode"] = string(metadata.BanditCode)
	}
	if len(metadata.ASVS) > 0 {
		tags["asvs"] = map[string]any(metadata.ASVS)
	}
	// Absent or redacted severity means the 0.5 impact is a default, not a
	// rating; the shared marker keeps that distinguishable downstream.
	normalized := severity
	if !isPresent(severity) {
		normalized = ""
	}
	shared.MarkUnratedSeverity(tags, normalized)
	return tags, nist
}

// buildRequirement folds every occurrence of one rule into a single
// requirement: semgrep metadata is rule-scoped and identical across
// occurrences, so only the location varies.
func buildRequirement(checkID string, results []Result, startTime time.Time) hdf.EvaluatedRequirement {
	representative := results[0]
	metadata := representative.Extra.Metadata
	tags, nist := tagsFor(metadata, checkID, string(representative.Extra.Severity))

	requirementResults := make([]hdf.RequirementResult, 0, len(results))
	for _, result := range results {
		message := messageFor(result)
		requirementResults = append(requirementResults, hdf.RequirementResult{
			// Semgrep reports only violations. Findings suppressed with a
			// `nosemgrep` comment are omitted from the output entirely rather
			// than flagged, so no skipped status is derivable.
			Status:    hdf.Failed,
			CodeDesc:  codeDescFor(result),
			Message:   &message,
			StartTime: startTime,
		})
	}

	title := titleFor(checkID)
	return hdf.EvaluatedRequirement{
		ID:                 checkID,
		Title:              &title,
		Impact:             impactFor(representative),
		Tags:               tags,
		Cwe:                cweCatalogFor(metadata),
		Refs:               refsFor(metadata),
		SourceLocation:     sourceLocationFor(representative),
		Code:               codeFor(representative),
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       []hdf.Description{{Label: "default", Data: string(representative.Extra.Message)}},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		Results:            requirementResults,
	}
}

// codeEnvelope is the curated match envelope serialized into requirement.code
// for the CODE tab: the rule source itself is not present in semgrep's JSON
// output, and the raw finding bytes are not byte-stable across the Go/TS pair
// (escape forms differ), so both languages serialize this envelope field-for-
// field in the same order. Rule metadata is deliberately excluded — it is
// already carried structurally in tags, cwe[], and refs[] — and redacted
// fields are filtered per the converter's redaction policy.
type codeEnvelope struct {
	CheckID string        `json:"check_id"`
	Path    string        `json:"path,omitempty"`
	Start   *codePosition `json:"start,omitempty"`
	End     *codePosition `json:"end,omitempty"`
	Extra   *codeExtra    `json:"extra,omitempty"`
}

type codePosition struct {
	Line int `json:"line"`
	Col  int `json:"col,omitempty"`
}

type codeExtra struct {
	Message  string `json:"message,omitempty"`
	Severity string `json:"severity,omitempty"`
	Lines    string `json:"lines,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

func codePositionFor(position Position) *codePosition {
	if position.Line <= 0 {
		return nil
	}
	out := &codePosition{Line: int(position.Line)}
	if position.Col > 0 {
		out.Col = int(position.Col)
	}
	return out
}

func codeFor(result Result) *string {
	envelope := codeEnvelope{
		CheckID: string(result.CheckID),
		Start:   codePositionFor(result.Start),
		End:     codePositionFor(result.End),
	}
	if isPresent(result.Path) {
		envelope.Path = string(result.Path)
	}
	extra := codeExtra{}
	if isPresent(result.Extra.Message) {
		extra.Message = string(result.Extra.Message)
	}
	if isPresent(result.Extra.Severity) {
		extra.Severity = string(result.Extra.Severity)
	}
	if isPresent(result.Extra.Lines) {
		extra.Lines = string(result.Extra.Lines)
	}
	if isPresent(result.Extra.Fix) {
		extra.Fix = string(result.Extra.Fix)
	}
	if extra != (codeExtra{}) {
		envelope.Extra = &extra
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(envelope); err != nil {
		return nil
	}
	return hdfutil.Ptr(strings.TrimSuffix(buf.String(), "\n"))
}

// buildErrorsRequirement surfaces scan failures so a file that failed to parse
// is visible: absence of findings in it is not evidence of compliance.
// errors[].level drives the status: level "error" entries are scan failures
// (status error), while level "warn" entries are advisory (e.g. PartialParsing
// — the file was partially analyzed), a genuine non-evaluation of those paths
// that must not dominate worst-wins rollups, so they map to notReviewed.
func buildErrorsRequirement(errors []ScanError, startTime time.Time) hdf.EvaluatedRequirement {
	results := make([]hdf.RequirementResult, 0, len(errors))
	for _, scanError := range errors {
		kind := "Unknown"
		if list, ok := scanError.Type.([]any); ok && len(list) > 0 {
			kind = fmt.Sprintf("%v", list[0])
		} else if scanError.Type != nil {
			kind = fmt.Sprintf("%v", scanError.Type)
		}
		path := string(scanError.Path)
		if path == "" {
			path = "unknown"
		}
		status := hdf.Error
		message := fmt.Sprintf("%s: %s", kind, scanError.Message)
		if level := string(scanError.Level); level != "" {
			message = fmt.Sprintf("%s [%s]: %s", kind, level, scanError.Message)
			if strings.EqualFold(level, "warn") {
				status = hdf.NotReviewed
			}
		}
		results = append(results, hdf.RequirementResult{
			Status:    status,
			CodeDesc:  fmt.Sprintf("Path: %s", path),
			Message:   &message,
			StartTime: startTime,
		})
	}

	title := "Semgrep scan errors"
	tags := map[string]any{"nist": append([]string(nil), shared.DefaultStaticAnalysisNIST...)}
	// The 0.5 impact on this synthesized requirement is a default, not a
	// severity rating from the tool.
	shared.MarkUnratedSeverity(tags, "")
	return hdf.EvaluatedRequirement{
		ID:     scanErrorsID,
		Title:  &title,
		Impact: defaultImpact,
		Tags:   tags,
		Descriptions: []hdf.Description{{
			Label: "default",
			Data:  "Errors reported by Semgrep while scanning. A file that failed to parse was not fully analyzed.",
		}},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		Results:            results,
	}
}

// buildCoverageRequirement records the scan's denominator. Semgrep reports
// violations only, so a converted profile is failures-only by construction and
// its compliance ratio is not a pass rate; this record carries the scanned
// count and the caveat. Impact 0 makes ComputeEffectiveStatus derive
// notApplicable — the only status the compliance rollup excludes — and the raw
// status matches so raw-status consumers (and CKL export, where Passed would
// render NotAFinding) agree with the effective view. Mirrors kics-scan-coverage.
func buildCoverageRequirement(report Report, ruleCount int, startTime time.Time) hdf.EvaluatedRequirement {
	summary := fmt.Sprintf(
		"Semgrep scanned %d file(s); %d rule(s) produced findings and %d scan error(s) were reported. "+
			"Semgrep reports violations only and does not enumerate the rules that ran without "+
			"finding anything, so no passing requirements can be derived from its output and the "+
			"compliance ratio should not be read as a pass rate.",
		len(report.Paths.Scanned), ruleCount, len(report.Errors))

	title := "Semgrep scan coverage"
	return hdf.EvaluatedRequirement{
		ID:           coverageID,
		Title:        &title,
		Impact:       0,
		Descriptions: []hdf.Description{{Label: "default", Data: summary}},
		Tags: map[string]any{
			"filesScanned":      len(report.Paths.Scanned),
			"rulesWithFindings": ruleCount,
			"scanErrors":        len(report.Errors),
		},
		Results: []hdf.RequirementResult{{
			Status:    hdf.NotApplicable,
			CodeDesc:  summary,
			StartTime: startTime,
		}},
	}
}

func jsonValueHasPrefix(raw json.RawMessage, prefix byte) bool {
	trimmed := strings.TrimSpace(string(raw))
	return len(trimmed) > 0 && trimmed[0] == prefix
}

// ConvertSemgrepToHDF converts native `semgrep scan --json` output to HDF.
// SARIF input is detected and delegated to the SARIF converter.
func ConvertSemgrepToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateJSONSize(input, "semgrep", 0); err != nil {
		return nil, fmt.Errorf("semgrep: %w", err)
	}
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, fmt.Errorf("semgrep: empty input")
	}

	// Format routing: semgrep also emits SARIF; delegate transparently.
	if result := registry.DetectConverter(input); result != nil && result.Fingerprint.ID == "sarif-to-hdf" {
		return sarif.ConvertSarifToHDF(input, converterVersion)
	}

	// Decoded loosely first so a document whose containers are missing or not
	// arrays is rejected as "not semgrep" — matching the TypeScript guard and
	// this converter's own fingerprint, which score the same bytes zero.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(input, &probe); err != nil {
		return nil, fmt.Errorf("semgrep: failed to parse report: %w", err)
	}
	if !jsonValueHasPrefix(probe["results"], '[') || !jsonValueHasPrefix(probe["errors"], '[') {
		return nil, fmt.Errorf("semgrep: input does not look like a Semgrep report")
	}

	var report Report
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("semgrep: failed to parse report: %w", err)
	}

	startTime := time.Now().UTC()

	// Group by rule, preserving the order rules were first seen. Go randomizes
	// map iteration, so the order is tracked separately.
	groups := make(map[string][]Result)
	order := make([]string, 0, len(report.Results))
	for _, result := range report.Results {
		checkID := string(result.CheckID)
		if checkID == "" {
			continue
		}
		if _, seen := groups[checkID]; !seen {
			order = append(order, checkID)
		}
		groups[checkID] = append(groups[checkID], result)
	}

	requirements := make([]hdf.EvaluatedRequirement, 0, len(order)+3)
	for _, checkID := range order {
		requirements = append(requirements, buildRequirement(checkID, groups[checkID], startTime))
	}
	if len(order) == 0 {
		requirements = append(requirements, shared.BuildNoFindingsRequirement(
			"semgrep-no-findings",
			fmt.Sprintf("Semgrep scanned %d file(s) and reported no findings.", len(report.Paths.Scanned)),
			startTime,
		))
	}
	if len(report.Errors) > 0 {
		requirements = append(requirements, buildErrorsRequirement(report.Errors, startTime))
	}
	requirements = append(requirements, buildCoverageRequirement(report, len(order), startTime))

	title := "Semgrep static analysis scan"
	baseline := hdf.EvaluatedBaseline{
		Name:            "Semgrep Scan",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: shared.InputChecksum(input),
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "semgrep-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Semgrep",
		ToolVersion:      string(report.Version),
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &startTime,
	}), nil
}
