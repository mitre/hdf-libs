// Package kics converts native `kics scan --report-formats json` output to HDF.
//
// KICS also emits SARIF, which carries its CWE taxonomy properly. What SARIF
// drops is the remediation pair (expected_value), the add-a-block versus
// fix-a-value distinction (issue_type), the stable finding fingerprint
// (similarity_id), and one level of severity granularity — CRITICAL and HIGH
// both become `error`.
package kics

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// KICS publishes five severities; SARIF collapses CRITICAL and HIGH into
// `error`, and keeping them apart is much of why this converter exists. The
// shared standard map covers four of them, with info at the canonical 0.0
// tier like every other converter: the effective-status layer maps impact-0
// requirements to notApplicable, so info-tier findings stay visible in the
// output without entering the compliance ratio. TRACE is KICS-specific and
// joins the info tier as an alias.
var kicsSeverityAliases = map[string]float64{"trace": 0.0}

const defaultImpact = 0.5

// Records which tier resolved a requirement's NIST tags, so a reviewed mapping
// stays distinguishable from a CWE-derived guess and from a static default.
// Follows the precedent set by MarkUnratedSeverity, which exists so a defaulted
// impact stays distinguishable from a genuine rated one.
//
// The per-query table is authoritative, matching how the Checkov and AWS Config
// mappers in the v1 line work: the rule-to-control decision is reviewed before
// shipping rather than computed at conversion time. CWE is a fallback because
// it is a lossy proxy — only 30 of the 102 CWEs KICS uses resolve against the
// CWE-to-NIST table, 52% of queries by volume.
const (
	nistMappingTag      = "nistMapping"
	nistMappingTable    = "mapped"
	nistMappingCWE      = "cwe-derived"
	nistMappingFallback = "static-fallback"
)

var (
	cweDigits = regexp.MustCompile(`^\d+$`)
	cwePrefix = regexp.MustCompile(`(?i)^CWE-`)
)

func impactFor(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, kicsSeverityAliases, defaultImpact)
}

// cweIdentifiers normalizes KICS's bare number form, e.g. "778".
func cweIdentifiers(q Query) []string {
	id := strings.TrimSpace(q.CWE)
	if id == "" {
		return nil
	}
	id = cwePrefix.ReplaceAllString(id, "")
	if !cweDigits.MatchString(id) {
		return nil
	}
	return []string{"CWE-" + id}
}

// ResolveControls returns the NIST and CCI tags for a query along with the tier
// that produced them: the reviewed per-query table, then the query's CWE, then
// the static-analysis defaults. The table is a parameter so all three tiers are
// testable without shipping unreviewed rows in the table itself.
func ResolveControls(q Query, table map[string]MappingEntry) (nist []string, ccis []string, source string) {
	if entry, ok := table[q.QueryID]; ok && len(entry.NIST) > 0 {
		return entry.NIST, entry.CCI, nistMappingTable
	}

	// shared.MapCWEToNIST dedups and sorts, matching the TS mapCWEToNIST.
	if fromCWE := shared.MapCWEToNIST(cweIdentifiers(q), nil); len(fromCWE) > 0 {
		return fromCWE, cci.NISTToCCI(fromCWE), nistMappingCWE
	}

	fallback := append([]string(nil), shared.DefaultStaticAnalysisNIST...)
	return fallback, cci.NISTToCCI(fallback), nistMappingFallback
}

func locationFor(f File) string {
	parts := []string{"File: " + orUnknown(f.FileName)}
	if f.Line > 0 {
		parts = append(parts, fmt.Sprintf("Line: %d", f.Line))
	}
	if f.ResourceType != "" {
		parts = append(parts, "Resource type: "+f.ResourceType)
	}
	if f.ResourceName != "" && f.ResourceName != "unknown" {
		parts = append(parts, "Resource: "+f.ResourceName)
	}
	if f.SearchKey != "" {
		parts = append(parts, "Key: "+f.SearchKey)
	}
	// KICS's own stable per-occurrence fingerprint; the identity SARIF drops.
	if f.SimilarityID != "" {
		parts = append(parts, "Similarity ID: "+f.SimilarityID)
	}
	return strings.Join(parts, "\n")
}

// evidenceFor builds the remediation pair. SARIF keeps only actual_value inside
// its message, so a SARIF-derived control can say what the configuration is but
// never what it should be.
func evidenceFor(f File) string {
	var parts []string
	if f.ExpectedValue != "" {
		parts = append(parts, "Expected: "+f.ExpectedValue)
	}
	if f.ActualValue != "" {
		parts = append(parts, "Actual: "+f.ActualValue)
	}
	if f.IssueType != "" {
		parts = append(parts, "Issue type: "+f.IssueType)
	}
	if f.SearchValue != "" {
		parts = append(parts, "Search value: "+f.SearchValue)
	}
	return strings.Join(parts, "\n")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// jsonValueHasPrefix reports whether a raw JSON value starts with the given
// byte after leading whitespace — '[' for an array, '"' for a string. A nil
// raw value (key absent) fails.
func jsonValueHasPrefix(raw json.RawMessage, prefix byte) bool {
	trimmed := strings.TrimSpace(string(raw))
	return len(trimmed) > 0 && trimmed[0] == prefix
}

func distinct(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func tagsFor(q Query) (map[string]any, []string) {
	nist, ccis, source := ResolveControls(q, KicsMappingData)
	tags := map[string]any{"nist": nist}
	if len(ccis) > 0 {
		tags["cci"] = ccis
	}
	tags[nistMappingTag] = source
	// Kept even when it does not resolve: an unmapped CWE that is invisible in
	// the output is a gap nobody can see.
	if cwe := cweIdentifiers(q); len(cwe) > 0 {
		tags["cwe"] = cwe
	}
	if q.Severity != "" {
		tags["severity"] = q.Severity
	}
	if q.Platform != "" {
		tags["platform"] = q.Platform
	}
	if q.CloudProvider != "" {
		tags["cloudProvider"] = q.CloudProvider
	}
	if q.Category != "" {
		tags["category"] = q.Category
	}
	if q.QueryURL != "" {
		tags["queryUrl"] = q.QueryURL
	}
	if q.RiskScore != nil {
		switch v := q.RiskScore.(type) {
		case string:
			tags["riskScore"] = v
		case float64:
			// plain decimal notation, matching TS String() for any value in
			// and far beyond KICS's 0-10 risk_score range
			tags["riskScore"] = strconv.FormatFloat(v, 'f', -1, 64)
		default:
			tags["riskScore"] = fmt.Sprintf("%v", v)
		}
	}
	if q.DescriptionID != "" {
		tags["descriptionId"] = q.DescriptionID
	}
	if q.Experimental {
		tags["experimental"] = true
	}
	issue := make([]string, 0, len(q.Files))
	resource := make([]string, 0, len(q.Files))
	for _, f := range q.Files {
		issue = append(issue, f.IssueType)
		resource = append(resource, f.ResourceType)
	}
	if v := distinct(issue); len(v) > 0 {
		tags["issueType"] = v
	}
	if v := distinct(resource); len(v) > 0 {
		tags["resourceType"] = v
	}
	shared.MarkUnratedSeverity(tags, q.Severity)
	return tags, nist
}

// buildCoverageRequirement records the denominator KICS otherwise reports only
// in top-level counters.
//
// KICS reports violations only. Its output carries no record of the queries that
// ran without finding anything — queries[] contains only those that fired — so
// no passing requirement can be derived from it, and a converted profile is
// failures-only by construction. That makes the compliance percentage
// misleading on its own: a scan where 72 of 2,034 queries fired renders as 100%
// failed. This record carries the denominator so the ratio is legible.
//
// Impact 0 and status notApplicable both keep it out of the score: the
// effective-status layer (ComputeEffectiveStatus) maps impact-0 requirements
// to notApplicable before statuses are counted, and notApplicable is the one
// status the compliance rollup excludes from both numerator and denominator.
// Emitting notApplicable as the raw status too keeps raw-status consumers
// agreeing with the effective view — Passed would export to CKL as
// NotAFinding, a compliant-looking control that was never checked, and count
// as a free pass in raw status rollups.
func buildCoverageRequirement(report Report, startTime time.Time) hdf.EvaluatedRequirement {
	fired := 0
	for _, q := range report.Queries {
		if len(q.Files) > 0 {
			fired++
		}
	}
	summary := fmt.Sprintf(
		"KICS executed %d queries against %d file(s) (%d parsed); %d produced findings. "+
			"KICS reports violations only and does not enumerate the queries that ran "+
			"without finding anything, so no passing requirements can be derived from "+
			"its output and the compliance ratio should not be read as a pass rate.",
		report.QueriesTotal, report.FilesScanned, report.FilesParsed, fired)

	title := "KICS scan coverage"
	return hdf.EvaluatedRequirement{
		ID:           "kics-scan-coverage",
		Title:        &title,
		Impact:       0,
		Descriptions: []hdf.Description{{Label: "default", Data: summary}},
		Tags: map[string]any{
			"queriesExecuted":        report.QueriesTotal,
			"queriesWithFindings":    fired,
			"filesScanned":           report.FilesScanned,
			"filesParsed":            report.FilesParsed,
			"filesFailedToScan":      report.FilesFailedToScan,
			"queriesFailedToExecute": report.QueriesFailedToRun,
		},
		Results: []hdf.RequirementResult{{
			Status:    hdf.NotApplicable,
			CodeDesc:  summary,
			StartTime: startTime,
		}},
	}
}

func buildRequirement(q Query, startTime time.Time) hdf.EvaluatedRequirement {
	tags, nist := tagsFor(q)

	results := make([]hdf.RequirementResult, 0, len(q.Files))
	for _, f := range q.Files {
		msg := evidenceFor(f)
		results = append(results, hdf.RequirementResult{
			// KICS reports only violations; there is no passing or suppressed
			// state in its output to derive anything else from.
			Status:    hdf.Failed,
			CodeDesc:  locationFor(f),
			Message:   &msg,
			StartTime: startTime,
		})
	}

	id := q.QueryID
	if id == "" {
		id = q.QueryName
	}
	title := q.QueryName
	if title == "" {
		title = q.QueryID
	}
	if title == "" {
		title = "Unnamed KICS query"
	}
	return hdf.EvaluatedRequirement{
		ID:                 orUnknown(id),
		Title:              &title,
		Impact:             impactFor(q.Severity),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       []hdf.Description{{Label: "default", Data: q.Description}},
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		Results:            results,
	}
}

// ConvertKicsToHDF converts native KICS JSON output to HDF.
func ConvertKicsToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateJSONSize(input, "kics", 0); err != nil {
		return nil, fmt.Errorf("kics: %w", err)
	}
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, fmt.Errorf("kics: empty input")
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(input, &probe); err != nil {
		return nil, fmt.Errorf("kics: failed to parse report: %w", err)
	}
	// Type-check, not just presence: a truncated or filtered report with
	// queries:null must not convert to a clean no-findings document. Mirrors
	// the fingerprint's array/string checks so convert and auto-detect agree.
	if !jsonValueHasPrefix(probe["queries"], '[') || !jsonValueHasPrefix(probe["kics_version"], '"') {
		return nil, fmt.Errorf("kics: input does not look like a KICS report")
	}

	var report Report
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("kics: failed to parse report: %w", err)
	}

	startTime := time.Now().UTC()
	requirements := make([]hdf.EvaluatedRequirement, 0, len(report.Queries))
	for _, q := range report.Queries {
		if len(q.Files) == 0 {
			continue
		}
		requirements = append(requirements, buildRequirement(q, startTime))
	}
	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"kics-no-findings",
				fmt.Sprintf("KICS scanned %d file(s) and reported no findings.", report.FilesScanned),
				startTime,
			),
		}
	}
	requirements = append(requirements, buildCoverageRequirement(report, startTime))

	title := "KICS infrastructure-as-code scan"
	baseline := hdf.EvaluatedBaseline{
		Name:            "KICS Scan",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: shared.InputChecksum(input),
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "kics-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "KICS",
		ToolVersion:      report.KicsVersion,
		ToolFormat:       "json",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &startTime,
	}), nil
}
