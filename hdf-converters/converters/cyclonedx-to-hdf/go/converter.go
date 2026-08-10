package cyclonedx_to_hdf

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	bomshared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/bom"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// CycloneDXBom is the top-level CycloneDX BOM structure.
type CycloneDXBom struct {
	BomFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Metadata        *CDXMetadata       `json:"metadata"`
	Components      []CDXComponent     `json:"components"`
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities"`
}

// CDXMetadata holds BOM metadata.
type CDXMetadata struct {
	Timestamp string                `json:"timestamp"`
	Component *CDXMetadataComponent `json:"component"`
}

// CDXMetadataComponent describes the top-level project component.
type CDXMetadataComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	BomRef  string `json:"bom-ref"`
}

// CDXComponent represents a single CycloneDX component.
type CDXComponent struct {
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	Group      string         `json:"group"`
	BomRef     string         `json:"bom-ref"`
	Components []CDXComponent `json:"components"`
}

// CDXVulnerability represents a single vulnerability entry.
type CDXVulnerability struct {
	ID             string         `json:"id"`
	Source         *CDXSource     `json:"source"`
	References     []CDXReference `json:"references"`
	Advisories     []CDXAdvisory  `json:"advisories"`
	Ratings        []CDXRating    `json:"ratings"`
	CWEs           []int          `json:"cwes"`
	Description    string         `json:"description"`
	Detail         string         `json:"detail"`
	Recommendation string         `json:"recommendation"`
	Created        string         `json:"created"`
	Published      string         `json:"published"`
	Updated        string         `json:"updated"`
	Affects        []CDXAffect    `json:"affects"`
	Analysis       *CDXAnalysis   `json:"analysis"`
}

// CDXSource identifies the advisory source.
type CDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// CDXReference is a cross-referenced vulnerability identifier and its source.
type CDXReference struct {
	ID     string     `json:"id"`
	Source *CDXSource `json:"source"`
}

// CDXAdvisory is an external advisory link for a vulnerability.
type CDXAdvisory struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// CDXRating holds a vulnerability rating (CVSS score and/or severity).
type CDXRating struct {
	Source   *CDXSource `json:"source"`
	Score    *float64   `json:"score"`
	Severity string     `json:"severity"`
	Method   string     `json:"method"`
	Vector   string     `json:"vector"`
}

// CDXAffect identifies a component affected by a vulnerability.
type CDXAffect struct {
	Ref string `json:"ref"`
}

// CDXAnalysis holds the vulnerability analysis (VEX).
type CDXAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification"`
	Response      []string `json:"response"`
	Detail        string   `json:"detail"`
}

// vexJustification maps a CycloneDX analysis.justification value to the HDF
// Justification controlled vocabulary. Returns nil for an empty or unmapped
// value — the free-text justification still rides in the override reason.
func vexJustification(j string) *hdf.Justification {
	var out hdf.Justification
	switch j {
	case "code_not_present":
		out = hdf.VulnerableCodeNotPresent
	case "code_not_reachable":
		out = hdf.VulnerableCodeNotInExecutePath
	case "requires_configuration":
		out = hdf.RequiresConfiguration
	case "requires_dependency":
		out = hdf.RequiresDependency
	case "requires_environment":
		out = hdf.RequiresEnvironment
	case "protected_by_compiler":
		out = hdf.ProtectedByCompiler
	case "protected_at_runtime":
		out = hdf.ProtectedAtRuntime
	case "protected_at_perimeter":
		out = hdf.ProtectedAtPerimeter
	case "protected_by_mitigating_control":
		out = hdf.InlineMitigationsAlreadyExist
	default:
		return nil
	}
	return &out
}

// analysisAppliedAt resolves the override's decision time. CycloneDX VEX carries
// no owner/date on the analysis block, so the vulnerability's own updated ->
// published -> created time is the defensible decision time; falls back to the
// finding's scan time only when the vuln carries no parseable date (keeping the
// override deterministic rather than reaching for now()).
func analysisAppliedAt(vuln CDXVulnerability, fallback time.Time) time.Time {
	for _, s := range []string{vuln.Updated, vuln.Published, vuln.Created} {
		if s == "" {
			continue
		}
		if t := hdfutil.ParseTimestamp(s); !t.IsZero() {
			return t
		}
	}
	return fallback
}

// analysisReason folds the CycloneDX analysis detail and response[] hints into a
// single override reason. Falls back to a short state-derived constant so the
// schema-required reason is never empty.
func analysisReason(a *CDXAnalysis) string {
	reason := a.Detail
	if len(a.Response) > 0 {
		ctx := "Response: " + strings.Join(a.Response, ", ")
		if reason == "" {
			reason = ctx
		} else {
			reason = reason + " (" + ctx + ")"
		}
	}
	if reason == "" {
		reason = "Dismissed via CycloneDX VEX analysis: " + a.State
	}
	return reason
}

// analysisOverride reconstructs a structured HDF status override from a CycloneDX
// VEX analysis block. Raw result status stays Failed; the attributed, expiring
// override carries the triage decision:
//   - not_affected / false_positive -> falsePositive, effectiveStatus notApplicable
//     (a vulnerability/SCA scan: the flagged vuln does not apply to this system).
//   - resolved / resolved_with_pedigree -> attestation, effectiveStatus passed
//     (the finding was remediated; resolved_with_pedigree carries the evidence).
//
// Returns (nil, nil, nil) when the analysis is absent or the state leaves the
// finding actionable (exploitable / in_triage / unknown) — those keep the raw
// Failed result with no override.
func analysisOverride(vuln CDXVulnerability, fallback time.Time) (*hdf.StatusOverride, *hdf.ResultStatus, *hdf.OverrideType) {
	if vuln.Analysis == nil {
		return nil, nil, nil
	}
	var oType hdf.OverrideType
	var effective hdf.ResultStatus
	switch vuln.Analysis.State {
	case "not_affected", "false_positive":
		oType = hdf.FalsePositive
		effective = hdf.NotApplicable
	case "resolved", "resolved_with_pedigree":
		oType = hdf.Attestation
		effective = hdf.Passed
	default:
		return nil, nil, nil
	}
	appliedAt := analysisAppliedAt(vuln, fallback)
	override := hdf.StatusOverride{
		Type:      oType,
		Status:    &effective,
		Reason:    analysisReason(vuln.Analysis),
		AppliedBy: hdf.Identity{Type: hdf.IdentityTypeOther, Identifier: "cyclonedx analysis"},
		AppliedAt: appliedAt,
		ExpiresAt: appliedAt.AddDate(1, 0, 0),
	}
	if j := vexJustification(vuln.Analysis.Justification); j != nil {
		override.Justification = j
	}
	return &override, &effective, &oType
}

// severityToImpact maps CycloneDX severity strings to HDF impact values.
// Standard mappings cover critical, high, medium, low, info, none.
// "unknown" and unrecognized values default to 0.5.
func severityToImpact(severity string) float64 {
	return hdfutil.SeverityToImpact(severity, 0.5)
}

var cvssMethods = map[string]bool{
	"CVSSv2":  true,
	"CVSSv3":  true,
	"CVSSv31": true,
	"CVSSv4":  true,
}

// cvssVersionFromMethod derives the CVSS version, preferring an explicit
// "CVSS:x.y/" vector prefix (the precise 3.0-vs-3.1 signal) and using the
// CycloneDX rating method to rescue the prefix-less v2/v4 vectors that would
// otherwise default to 3.1.
func cvssVersionFromMethod(method, vector string) hdf.Version {
	if strings.HasPrefix(vector, "CVSS:") {
		return shared.CvssVersionFromVector(vector)
	}
	switch method {
	case "CVSSv2":
		return shared.CvssVersionFromString("2.0")
	case "CVSSv4":
		return shared.CvssVersionFromString("4.0")
	default:
		return shared.CvssVersionFromVector(vector)
	}
}

// maxImpact computes the maximum impact across all ratings for a vulnerability.
// Prefers CVSS score/10 when available, falls back to severityToImpact().
func maxImpact(ratings []CDXRating) float64 {
	if len(ratings) == 0 {
		return 0.5
	}

	maxVal := 0.0
	for _, r := range ratings {
		var impact float64
		if cvssMethods[r.Method] && r.Score != nil {
			impact = *r.Score / 10
		} else {
			sev := r.Severity
			if sev == "" {
				sev = "medium"
			}
			impact = severityToImpact(sev)
		}
		if impact > maxVal {
			maxVal = impact
		}
	}
	return maxVal
}

// NOTE: heimdall2 mapped info/unknown severity to NotReviewed status.
// We intentionally do NOT replicate that behavior — a vulnerability is a
// finding regardless of severity confidence. Info/unknown severity vulns
// are Failed with impact derived from the severity mapping (info→0.1,
// unknown→0.5). NotReviewed means "not evaluated" which is incorrect
// when a scanner has identified a CVE.

// buildCvssEntries assembles structured requirement.cvss[] entries from the
// CycloneDX ratings. A rating contributes an entry only when it carries a CVSS
// method (CVSSv2/v3/v31/v4) and at least a score or a vector — ratings that only
// state a qualitative severity (method "other") carry no CVSS metrics and are
// left out, their severity already reflected in the requirement impact.
func buildCvssEntries(ratings []CDXRating) []hdf.Cvss {
	var entries []hdf.Cvss
	for _, r := range ratings {
		if !cvssMethods[r.Method] || (r.Score == nil && r.Vector == "") {
			continue
		}
		source := ""
		if r.Source != nil {
			source = r.Source.Name
		}
		entries = append(entries, shared.BuildCvss(shared.CvssInput{
			Version:    cvssVersionFromMethod(r.Method, r.Vector),
			BaseScore:  r.Score,
			BaseVector: r.Vector,
			Source:     source,
		}))
	}
	return entries
}

// buildRefs collects the external reference links a vulnerability carries — the
// advisory source URL, each cross-reference's source URL, and each advisory URL
// — de-duplicated across all three in first-seen order. Returns nil when the
// vulnerability carries no links.
func buildRefs(vuln CDXVulnerability) []hdf.Reference {
	seen := make(map[string]bool)
	var refs []hdf.Reference
	add := func(url string) {
		if url == "" || seen[url] {
			return
		}
		seen[url] = true
		u := url
		refs = append(refs, hdf.Reference{URL: &u})
	}
	if vuln.Source != nil {
		add(vuln.Source.URL)
	}
	for _, r := range vuln.References {
		if r.Source != nil {
			add(r.Source.URL)
		}
	}
	for _, a := range vuln.Advisories {
		add(a.URL)
	}
	return refs
}

// formatCodeDesc formats a component reference as a code_desc string.
func formatCodeDesc(componentLookup map[string]CDXComponent, ref string) string {
	comp, found := componentLookup[ref]
	if !found {
		// VEX case: no matching component, use the ref directly
		return fmt.Sprintf("Component %s is vulnerable", ref)
	}

	var name string
	if comp.Group != "" {
		name = comp.Group + "/"
	}
	name += comp.Name
	if comp.Version != "" {
		name += "@" + comp.Version
	}
	return fmt.Sprintf("Component %s is vulnerable", name)
}

// hasMLModelComponent reports whether any (possibly nested) component is a
// machine-learning-model, i.e. the CycloneDX document is an AI-BOM.
func hasMLModelComponent(components []CDXComponent) bool {
	for _, comp := range flattenComponents(components) {
		if comp.Type == "machine-learning-model" {
			return true
		}
	}
	return false
}

// flattenComponents flattens nested CycloneDX components into a single slice.
func flattenComponents(components []CDXComponent) []CDXComponent {
	var result []CDXComponent
	for _, comp := range components {
		result = append(result, comp)
		if len(comp.Components) > 0 {
			result = append(result, flattenComponents(comp.Components)...)
		}
	}
	return result
}

// isoUTCTrailingZeros matches the trailing fractional zeros of an RFC3339 UTC timestamp.
var isoUTCTrailingZeros = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d*?)0+Z$`)

// canonicalTimestamp trims trailing fractional-second zeros from an RFC3339 UTC
// timestamp, leaving anything else untouched. Mirrors trimUtcFraction in
// hdf-utilities, which the TS serializer applies to every string it emits.
func canonicalTimestamp(s string) string {
	m := isoUTCTrailingZeros.FindStringSubmatch(s)
	if m == nil {
		return s
	}
	if m[2] == "" {
		return m[1] + "Z"
	}
	return m[1] + "." + m[2] + "Z"
}

// canonicalizeTimestamps applies canonicalTimestamp to every string in the raw
// document passthrough. Without it the trimming the TS serializer performs would
// make the same input yield two different documents.
func canonicalizeTimestamps(v interface{}) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			if s, ok := child.(string); ok {
				val[k] = canonicalTimestamp(s)
				continue
			}
			canonicalizeTimestamps(child)
		}
	case []interface{}:
		for i, child := range val {
			if s, ok := child.(string); ok {
				val[i] = canonicalTimestamp(s)
				continue
			}
			canonicalizeTimestamps(child)
		}
	}
}

// ConvertCycloneDXToHDF converts CycloneDX SBOM/VEX JSON to HDF format.
func ConvertCycloneDXToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("cyclonedx: empty input")
	}
	if err := shared.ValidateJSONSize(input, "cyclonedx", 0); err != nil {
		return nil, fmt.Errorf("cyclonedx: %w", err)
	}

	var bom CycloneDXBom
	if err := json.Unmarshal(input, &bom); err != nil {
		return nil, fmt.Errorf("cyclonedx: invalid JSON: %w", err)
	}

	if bom.BomFormat != "CycloneDX" {
		return nil, fmt.Errorf("cyclonedx: missing or invalid bomFormat (expected \"CycloneDX\", got %q)", bom.BomFormat)
	}

	if len(bom.Components) == 0 && len(bom.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("cyclonedx: input has neither components nor vulnerabilities")
	}

	if len(bom.Vulnerabilities) == 0 {
		if hasMLModelComponent(bom.Components) {
			return nil, fmt.Errorf("cyclonedx: this file is a CycloneDX AI-BOM (machine-learning-model inventory) with no vulnerabilities; " +
				"to import it into a system document, use:\n" +
				"  hdf system create <file> --from cyclonedx-mlbom")
		}
		return nil, fmt.Errorf("cyclonedx: this file is an SBOM inventory with no vulnerabilities; " +
			"to import SBOM data into a system document, use:\n" +
			"  hdf system create <sbom-file> --component-name <name>")
	}

	checksum := shared.InputChecksum(input)

	// Prefer the BOM creation time as the scan timestamp; fall back to now.
	scanTime := time.Now().UTC()
	if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
		if parsed := hdfutil.ParseTimestamp(bom.Metadata.Timestamp); !parsed.IsZero() {
			scanTime = parsed
		}
	}

	// Flatten nested components and build lookup by bom-ref
	allComponents := flattenComponents(bom.Components)
	componentLookup := make(map[string]CDXComponent, len(allComponents))
	for _, comp := range allComponents {
		if comp.BomRef != "" {
			componentLookup[comp.BomRef] = comp
		}
	}

	limitedVulns := shared.LimitSliceWithWarning(bom.Vulnerabilities, 0, "vulnerability")
	requirements := make([]hdf.EvaluatedRequirement, 0, len(limitedVulns))

	for _, vuln := range limitedVulns {
		ratings := vuln.Ratings
		impact := maxImpact(ratings)
		cweStrs := make([]string, len(vuln.CWEs))
		for i, c := range vuln.CWEs {
			cweStrs[i] = fmt.Sprintf("%d", c)
		}
		nist := shared.MapCWEToNIST(cweStrs, shared.DefaultStaticAnalysisNIST)
		cciTags := cci.NISTToCCI(nist)

		// CWE identifiers are first-class on requirement.cwe[]; the CWE→NIST
		// mapping is retained in tags.nist.
		var cwes []string
		if len(vuln.CWEs) > 0 {
			cwes = make([]string, len(vuln.CWEs))
			for i, c := range vuln.CWEs {
				cwes[i] = fmt.Sprintf("CWE-%d", c)
			}
		}

		tags := shared.BuildNISTCCITags(nist, cciTags)

		// Build descriptions (must always include a 'default' label per HDF schema)
		descriptions := []hdf.Description{}

		// Default description: description + detail
		var defaultParts []string
		if vuln.Description != "" {
			defaultParts = append(defaultParts, fmt.Sprintf("Description: %s", vuln.Description))
		}
		if vuln.Detail != "" {
			defaultParts = append(defaultParts, fmt.Sprintf("Detail: %s", vuln.Detail))
		}
		if len(defaultParts) > 0 {
			descriptions = append(descriptions, hdf.Description{
				Label: "default",
				Data:  strings.Join(defaultParts, "\n\n"),
			})
		} else {
			descriptions = append(descriptions, hdf.Description{
				Label: "default",
				Data:  vuln.ID,
			})
		}

		// Fix description: recommendation + workaround from analysis
		var fixParts []string
		if vuln.Recommendation != "" {
			fixParts = append(fixParts, vuln.Recommendation)
		}
		if vuln.Analysis != nil && vuln.Analysis.Detail != "" {
			fixParts = append(fixParts, fmt.Sprintf("Workaround: %s", vuln.Analysis.Detail))
		}
		if len(fixParts) > 0 {
			descriptions = append(descriptions, hdf.Description{
				Label: "fix",
				Data:  strings.Join(fixParts, "\n\n"),
			})
		}

		// Build results: one per affected component.
		// All vulnerabilities are Failed — info/unknown severity affects impact
		// score but not status (a vuln is a finding regardless of severity confidence).
		var results []hdf.RequirementResult
		if len(vuln.Affects) > 0 {
			for _, affect := range vuln.Affects {
				results = append(results, hdf.RequirementResult{
					Status:    hdf.Failed,
					CodeDesc:  formatCodeDesc(componentLookup, affect.Ref),
					StartTime: scanTime,
				})
			}
		} else {
			results = append(results, hdf.RequirementResult{
				Status:    hdf.Failed,
				CodeDesc:  fmt.Sprintf("Vulnerability %s", vuln.ID),
				StartTime: scanTime,
			})
		}

		title := vuln.ID
		if vuln.Source != nil && vuln.Source.Name != "" {
			title = fmt.Sprintf("%s (%s)", vuln.ID, vuln.Source.Name)
		}

		// verificationMethod is intentionally NOT set. CycloneDX carries both
		// machine-generated SBOM vulnerability data and human-authored VEX
		// statements (analyst assertions about CVE exploitability). The
		// converter cannot reliably distinguish the two, so stamping
		// "automated" would misclassify VEX-derived requirements.
		req := hdf.EvaluatedRequirement{
			ID:           vuln.ID,
			Title:        &title,
			Impact:       impact,
			Tags:         tags,
			Cvss:         buildCvssEntries(ratings),
			Cwe:          cwes,
			ControlType:  shared.DeriveControlTypeFromTags(nist),
			Descriptions: descriptions,
			Refs:         buildRefs(vuln),
			Results:      results,
		}

		// Reconstruct a structured override from the CycloneDX VEX analysis: the
		// raw Failed result stays, and the triage decision rides as an attributed,
		// expiring statusOverride that flips effectiveStatus.
		if override, eff, disp := analysisOverride(vuln, scanTime); override != nil {
			req.StatusOverrides = []hdf.StatusOverride{*override}
			req.EffectiveStatus = eff
			req.Disposition = disp
		}

		requirements = append(requirements, req)
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "CycloneDX Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	comp := hdf.Component{
		Type: hdf.Application,
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		comp.Name = bom.Metadata.Component.Name
		if bom.Metadata.Component.Version != "" {
			comp.Version = &bom.Metadata.Component.Version
		}
	}

	// Attach the CycloneDX BOM to the component as a generalized boms[] entry.
	// The shared BOM parser yields the normalized package inventory; the raw
	// manifest is also carried via document passthrough so no data is dropped.
	// Vuln-only inputs (no components) have no packages and carry the document only.
	if parsed, perr := bomshared.ParseBom(input); perr == nil && parsed.Normalized != nil {
		parts := bomshared.BuildBomParts{
			BOMType:  bomshared.BOMTypeSbom,
			Format:   bomshared.FormatCycloneDX,
			UniqueID: parsed.Normalized.UniqueID,
		}
		if len(parsed.Normalized.Packages) > 0 {
			parts.Packages = parsed.Normalized.Packages
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(input, &doc); err == nil {
			canonicalizeTimestamps(doc)
			parts.Document = doc
		}
		comp.Boms = []hdf.BillOfMaterials{*bomshared.BuildBom(parts)}
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "cyclonedx-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "CycloneDX",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       []hdf.Component{comp},
		Timestamp:        &scanTime,
	}), nil
}
