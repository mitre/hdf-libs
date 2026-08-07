// Package defectdojo_to_hdf converts DefectDojo REST API finding data
// (the /api/v2/findings/ response model) to HDF Results.
//
// DefectDojo is an aggregator that tracks findings across their triage
// lifecycle. Unlike a raw scanner export, its findings carry consumer triage
// decisions with provenance — in particular a risk acceptance nested under
// accepted_risks[] (owner, created, expiration_date, decision_details). That
// provenance is what lets this converter emit a real HDF Status_Override
// (a waiver) rather than flattening the decision into a status. The static
// input format is the DefectDojo findings response; the live fetcher produces
// the same bytes.
package defectdojo_to_hdf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// --- DefectDojo /api/v2/findings/ input model (subset) ---

type ddResponse struct {
	Results []ddFinding `json:"results"`
}

type ddFinding struct {
	ID               int              `json:"id"`
	Title            string           `json:"title"`
	Severity         string           `json:"severity"`
	Description      string           `json:"description"`
	Mitigation       string           `json:"mitigation"`
	Impact           string           `json:"impact"`
	References       string           `json:"references"`
	CWE              *int             `json:"cwe"`
	VulnerabilityIDs []ddVulnID       `json:"vulnerability_ids"`
	Cvssv3           *string          `json:"cvssv3"`
	Cvssv3Score      *float64         `json:"cvssv3_score"`
	Cvssv4           *string          `json:"cvssv4"`
	Cvssv4Score      *float64         `json:"cvssv4_score"`
	EpssScore        *float64         `json:"epss_score"`
	EpssPercentile   *float64         `json:"epss_percentile"`
	UniqueIDFromTool *string          `json:"unique_id_from_tool"`
	VulnIDFromTool   *string          `json:"vuln_id_from_tool"`
	FilePath         *string          `json:"file_path"`
	Line             *int             `json:"line"`
	ComponentName    *string          `json:"component_name"`
	ComponentVersion *string          `json:"component_version"`
	Service          *string          `json:"service"`
	Date             string           `json:"date"`
	Active           bool             `json:"active"`
	Verified         bool             `json:"verified"`
	FalseP           bool             `json:"false_p"`
	Duplicate        bool             `json:"duplicate"`
	IsMitigated      bool             `json:"is_mitigated"`
	RiskAccepted     bool             `json:"risk_accepted"`
	OutOfScope       bool             `json:"out_of_scope"`
	UnderReview      bool             `json:"under_review"`
	AcceptedRisks    []ddAcceptedRisk `json:"accepted_risks"`
	RelatedFields    *ddRelatedFields `json:"related_fields"`

	// raw is the finding exactly as DefectDojo emitted it. DefectDojo carries no
	// literal source snippet, so requirement.code is the whole finding re-indented
	// in place — preserving source key order and every field the typed struct
	// does not model, byte-identical to the TypeScript twin's
	// JSON.stringify(finding, null, 2).
	raw json.RawMessage
}

// UnmarshalJSON captures the source bytes for requirement.code before decoding
// the typed fields. The plain alias avoids unmarshal recursion.
func (f *ddFinding) UnmarshalJSON(data []byte) error {
	type plain ddFinding
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*f = ddFinding(p)
	f.raw = append(json.RawMessage(nil), data...)
	return nil
}

type ddVulnID struct {
	VulnerabilityID string `json:"vulnerability_id"`
}

type ddAcceptedRisk struct {
	Owner           json.Number `json:"owner"`          // user id in the raw response
	OwnerUsername   *string     `json:"owner_username"` // optional fetcher enrichment
	OwnerEmail      *string     `json:"owner_email"`    // optional fetcher enrichment
	Created         string      `json:"created"`
	ExpirationDate  *string     `json:"expiration_date"`
	Decision        string      `json:"decision"`
	DecisionDetails *string     `json:"decision_details"`
	Name            string      `json:"name"`
}

type ddRelatedFields struct {
	Test *ddTest `json:"test"`
}
type ddTest struct {
	TestType *ddTestType `json:"test_type"`
}
type ddTestType struct {
	Name string `json:"name"`
}

// deriveStatus maps DefectDojo triage state to an HDF raw status, raw-primary:
// what the tool reported is preserved; triage decisions ride in tags (and, for
// risk acceptance, an override). Explicit dispositions take precedence over the
// derived is_mitigated (DefectDojo auto-sets is_mitigated when a finding is
// false-positived or risk-accepted).
func deriveStatus(f ddFinding) hdf.ResultStatus {
	switch {
	case f.OutOfScope:
		return hdf.NotApplicable
	case f.FalseP:
		return hdf.Failed // reported by the tool; dismissed-as-FP rides in the tag
	case f.RiskAccepted:
		return hdf.Failed // real risk; the acceptance is a waiver override
	case f.IsMitigated:
		return hdf.Passed // genuine remediation
	case f.UnderReview:
		return hdf.NotReviewed
	default:
		return hdf.Failed // active / untriaged
	}
}

// triageTags preserves every DefectDojo triage boolean verbatim, always present,
// as source-intact passthrough (never a faked override).
func triageTags(f ddFinding) map[string]interface{} {
	return map[string]interface{}{
		"defectdojo/active":        f.Active,
		"defectdojo/verified":      f.Verified,
		"defectdojo/false_p":       f.FalseP,
		"defectdojo/is_mitigated":  f.IsMitigated,
		"defectdojo/risk_accepted": f.RiskAccepted,
		"defectdojo/out_of_scope":  f.OutOfScope,
		"defectdojo/under_review":  f.UnderReview,
	}
}

// riskAcceptanceOwner resolves the accepted-risk owner to an HDF Identity,
// preferring fetcher-enriched username/email over the raw user id.
func riskAcceptanceOwner(ar ddAcceptedRisk) hdf.Identity {
	switch {
	case ar.OwnerEmail != nil && *ar.OwnerEmail != "":
		return hdf.Identity{Type: hdf.Email, Identifier: *ar.OwnerEmail}
	case ar.OwnerUsername != nil && *ar.OwnerUsername != "":
		return hdf.Identity{Type: hdf.Username, Identifier: *ar.OwnerUsername}
	case ar.Owner.String() != "":
		return hdf.Identity{Type: hdf.Simple, Identifier: fmt.Sprintf("defectdojo-user-%s", ar.Owner.String())}
	default:
		return hdf.Identity{Type: hdf.Simple, Identifier: "defectdojo-risk-acceptance-owner"}
	}
}

// buildWaiverOverride turns a DefectDojo risk acceptance into an HDF waiver
// Status_Override. The HDF schema documents `waiver` as "risk accepted by
// Authorizing Official" (FedRAMP-aligned), which is exactly a DefectDojo
// decision=Accept. Raw status stays failed; effectiveStatus becomes passed with
// the full attributed, expiring override present — not laundering.
func buildWaiverOverride(ar ddAcceptedRisk) hdf.StatusOverride {
	passed := hdf.Passed
	reason := ar.Name
	if ar.DecisionDetails != nil && *ar.DecisionDetails != "" {
		reason = *ar.DecisionDetails
	}
	if reason == "" {
		reason = "Risk accepted in DefectDojo"
	}
	appliedAt := hdfutil.ParseTimestamp(ar.Created)
	if appliedAt.IsZero() {
		appliedAt = time.Now().UTC()
	}
	// expiresAt is REQUIRED by the schema. DefectDojo acceptances usually carry
	// an expiration; when absent, default to one year out so the waiver is
	// reviewed rather than treated as permanent.
	expiresAt := appliedAt.AddDate(1, 0, 0)
	if ar.ExpirationDate != nil {
		if parsed := hdfutil.ParseTimestamp(*ar.ExpirationDate); !parsed.IsZero() {
			expiresAt = parsed
		}
	}
	return hdf.StatusOverride{
		Type:      hdf.OverrideTypeWaiver,
		Status:    &passed,
		Reason:    reason,
		AppliedBy: riskAcceptanceOwner(ar),
		AppliedAt: appliedAt,
		ExpiresAt: expiresAt,
	}
}

var dateOnlyPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// parseFindingDate parses a DefectDojo finding `date`. That field is date-only
// (YYYY-MM-DD) and hdfutil.ParseTimestamp has no date-only layout, so a bare date
// is promoted to UTC midnight before canonical parsing. This keeps Go and TS
// byte-identical (the TS twin's parseTimestamp reads a bare date as UTC midnight
// too) and avoids Go silently dropping the source date and falling back to now().
func parseFindingDate(s string) time.Time {
	if dateOnlyPattern.MatchString(s) {
		s += "T00:00:00Z"
	}
	return hdfutil.ParseTimestamp(s)
}

// latestFindingDate returns the most recent finding `date`. DefectDojo's findings
// response carries no single top-level scan time, so the newest finding date is
// the defensible report time for the top-level HDF timestamp. Returns the zero
// time when no finding carries a parseable date — the caller then omits the
// optional top-level timestamp rather than fabricating a wall-clock value
// (keeping the mapping source-derived and deterministic).
func latestFindingDate(findings []ddFinding) time.Time {
	var latest time.Time
	for _, f := range findings {
		if d := parseFindingDate(f.Date); !d.IsZero() && d.After(latest) {
			latest = d
		}
	}
	return latest
}

func findingID(f ddFinding) string {
	switch {
	case f.UniqueIDFromTool != nil && *f.UniqueIDFromTool != "":
		return *f.UniqueIDFromTool
	case f.VulnIDFromTool != nil && *f.VulnIDFromTool != "":
		return *f.VulnIDFromTool
	default:
		return fmt.Sprintf("DefectDojo-Finding-%d", f.ID)
	}
}

func cveList(f ddFinding) []string {
	out := make([]string, 0, len(f.VulnerabilityIDs))
	for _, v := range f.VulnerabilityIDs {
		if v.VulnerabilityID != "" {
			out = append(out, v.VulnerabilityID)
		}
	}
	return out
}

func buildCvss(f ddFinding) []hdf.Cvss {
	var out []hdf.Cvss
	add := func(version hdf.Version, vector *string, score *float64) {
		if score == nil && (vector == nil || *vector == "") {
			return
		}
		var baseVector string
		if vector != nil {
			baseVector = *vector
		}
		out = append(out, shared.BuildCvss(shared.CvssInput{
			Version:    version,
			BaseScore:  score,
			BaseVector: baseVector,
		}))
	}
	add(hdf.The31, f.Cvssv3, f.Cvssv3Score)
	add(hdf.The40, f.Cvssv4, f.Cvssv4Score)
	return out
}

func buildEpss(f ddFinding) *hdf.Epss {
	// date is required on Epss; omit the block entirely when the finding has no date.
	if f.EpssScore == nil || f.Date == "" {
		return nil
	}
	pct := 0.0
	if f.EpssPercentile != nil {
		pct = *f.EpssPercentile
	}
	return &hdf.Epss{Score: *f.EpssScore, Percentile: pct, Date: f.Date}
}

func nistTags(f ddFinding) []string {
	if f.CWE != nil && *f.CWE > 0 {
		return shared.MapCWEToNIST([]string{fmt.Sprintf("CWE-%d", *f.CWE)}, shared.DefaultStaticAnalysisNIST)
	}
	return shared.DefaultStaticAnalysisNIST
}

func buildDescriptions(f ddFinding) []hdf.Description {
	descs := []hdf.Description{{Label: "default", Data: coalesceDesc(f.Description, f.Title)}}
	if f.Mitigation != "" {
		descs = append(descs, hdf.Description{Label: "fix", Data: f.Mitigation})
	}
	if f.Impact != "" {
		descs = append(descs, hdf.Description{Label: "impact", Data: f.Impact})
	}
	return descs
}

func coalesceDesc(desc, title string) string {
	if desc != "" {
		return desc
	}
	if title != "" {
		return title
	}
	return "No description provided."
}

func codeDesc(f ddFinding) string {
	parts := []string{f.Title}
	if f.ComponentName != nil && *f.ComponentName != "" {
		comp := *f.ComponentName
		if f.ComponentVersion != nil && *f.ComponentVersion != "" {
			comp = comp + "@" + *f.ComponentVersion
		}
		parts = append(parts, "Component: "+comp)
	}
	if f.FilePath != nil && *f.FilePath != "" {
		loc := *f.FilePath
		if f.Line != nil {
			loc = fmt.Sprintf("%s:%d", loc, *f.Line)
		}
		parts = append(parts, "Location: "+loc)
	}
	if cves := cveList(f); len(cves) > 0 {
		parts = append(parts, "CVE: "+strings.Join(cves, ", "))
	}
	return strings.Join(parts, " | ")
}

// buildFindingCode renders the raw DefectDojo finding as indented JSON for
// requirement.code (Heimdall's CODE tab). json.Indent reformats the original
// bytes in place, preserving source key order so the output matches the TS
// twin's JSON.stringify(finding, null, 2). Returns "" when no raw bytes are
// available (a synthesized finding) or the bytes are malformed, so the caller
// leaves code unset rather than emitting a placeholder.
func buildFindingCode(f ddFinding) string {
	if len(f.raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, f.raw, "", "  "); err != nil {
		return ""
	}
	return buf.String()
}

func convertFinding(f ddFinding) hdf.EvaluatedRequirement {
	nist := nistTags(f)
	tags := shared.BuildNISTCCITags(nist, cci.NISTToCCI(nist))
	for k, v := range triageTags(f) {
		tags[k] = v
	}

	// CVE → tags.cve (interim, pending a first-class identifiers[] field). The
	// requirement.id is a native DefectDojo finding id (DefectDojo-Finding-<n> or
	// a tool id), never the CVE, so the CVE list is not a duplicate of the id.
	if cves := cveList(f); len(cves) > 0 {
		tags["cve"] = cves
	}

	status := deriveStatus(f)
	startTime := parseFindingDate(f.Date)
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}
	result := hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc(f),
		StartTime: startTime,
	}

	req := hdf.EvaluatedRequirement{
		ID:           findingID(f),
		Impact:       hdfutil.SeverityToImpact(f.Severity, 0.5),
		Results:      []hdf.RequirementResult{result},
		Tags:         tags,
		Descriptions: buildDescriptions(f),
		ControlType:  shared.DeriveControlTypeFromTags(nist),
		Cvss:         buildCvss(f),
		Epss:         buildEpss(f),
	}

	if f.CWE != nil && *f.CWE > 0 {
		req.Cwe = []string{fmt.Sprintf("CWE-%d", *f.CWE)}
	}

	// KEV is NOT-IN-SOURCE: DefectDojo findings carry known_exploited/kev_date/
	// ransomware_used but no CISA remediation due date. hdf.Kev requires both
	// dateAdded AND dueDate when inKev is true, so a schema-valid requirement.kev
	// cannot be produced from source alone — synthesizing a dueDate DefectDojo
	// never sent would be fabrication. The KEV signal is preserved verbatim in
	// requirement.code (the raw finding JSON).

	if code := buildFindingCode(f); code != "" {
		req.Code = &code
	}

	// The novel part: a risk-accepted finding carries a real waiver override
	// (built from accepted_risks provenance), so raw failed + effectiveStatus
	// passed + disposition waiver are all present.
	if f.RiskAccepted && len(f.AcceptedRisks) > 0 {
		override := buildWaiverOverride(f.AcceptedRisks[0])
		waiver := hdf.OverrideTypeWaiver
		effective := hdf.Passed
		req.StatusOverrides = []hdf.StatusOverride{override}
		req.EffectiveStatus = &effective
		req.Disposition = &waiver
		req.Tags["defectdojo/decision"] = f.AcceptedRisks[0].Decision
	}

	return req
}

// scannerName returns the underlying DefectDojo test_type (the real scanner
// that produced the finding), used to group requirements into per-scanner
// baselines. Falls back to a generic label.
func scannerName(f ddFinding) string {
	if f.RelatedFields != nil && f.RelatedFields.Test != nil && f.RelatedFields.Test.TestType != nil && f.RelatedFields.Test.TestType.Name != "" {
		return f.RelatedFields.Test.TestType.Name
	}
	return "DefectDojo"
}

// ConvertDefectDojo converts a DefectDojo findings response to HDF Results.
func ConvertDefectDojo(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("defectdojo: empty input")
	}
	if err := shared.ValidateJSONSize(input, "defectdojo", 0); err != nil {
		return nil, fmt.Errorf("defectdojo: %w", err)
	}
	resultsChecksum := shared.InputChecksum(input)

	findings, err := parseFindings(input)
	if err != nil {
		return nil, err
	}

	// Group findings into per-scanner baselines, preserving encounter order.
	order := []string{}
	byScanner := map[string][]hdf.EvaluatedRequirement{}
	for _, f := range findings {
		name := scannerName(f)
		if _, seen := byScanner[name]; !seen {
			order = append(order, name)
		}
		byScanner[name] = append(byScanner[name], convertFinding(f))
	}

	var baselines []hdf.EvaluatedBaseline
	for _, name := range order {
		title := name
		baselines = append(baselines, hdf.EvaluatedBaseline{
			Name:            "DefectDojo: " + name,
			Title:           &title,
			Requirements:    byScanner[name],
			ResultsChecksum: resultsChecksum,
		})
	}

	// Empty response → one passed placeholder so the document validates.
	if len(baselines) == 0 {
		baselines = []hdf.EvaluatedBaseline{{
			Name: "DefectDojo",
			Requirements: []hdf.EvaluatedRequirement{
				shared.BuildNoFindingsRequirement(
					"defectdojo-no-findings",
					"DefectDojo reported zero findings.",
					time.Now().UTC(),
				),
			},
			ResultsChecksum: resultsChecksum,
		}}
	}

	opts := shared.HDFResultsOptions{
		GeneratorName:    "defectdojo-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "DefectDojo",
		Baselines:        baselines,
	}
	// Top-level timestamp: the newest finding date, source-derived and
	// deterministic. Omitted (nil) when no finding carries a parseable date.
	if ts := latestFindingDate(findings); !ts.IsZero() {
		opts.Timestamp = &ts
	}
	return shared.BuildHDFResults(opts), nil
}

// parseFindings accepts the DRF envelope {results:[…]} or a bare findings array.
func parseFindings(input []byte) ([]ddFinding, error) {
	var envelope ddResponse
	if err := json.Unmarshal(input, &envelope); err == nil && envelope.Results != nil {
		return envelope.Results, nil
	}
	var bare []ddFinding
	if err := json.Unmarshal(input, &bare); err == nil {
		return bare, nil
	}
	return nil, fmt.Errorf("defectdojo: input is neither a findings response envelope nor a findings array")
}
