// Package hdftooscalsar converts HDF Results to OSCAL Assessment Results (SAR) format.
//
// This is the reverse direction of the oscal-to-hdf SAR converter. It takes HDF
// Results JSON and produces an OSCAL 1.1.2 assessment-results JSON document.
package hdftooscalsar

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ConvertHDFToOSCALSAR converts HDF Results JSON bytes to OSCAL Assessment
// Results JSON bytes. The converterVersion parameter is unused but present
// to conform to the RawConvertFn signature.
func ConvertHDFToOSCALSAR(input []byte, _ string) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "hdf-to-oscal-sar", 0); err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-oscal-sar: empty input")
	}

	var hdfResults hdf.HDFResults
	if err := shared.DecodeHDF(input, &hdfResults); err != nil {
		return nil, fmt.Errorf("hdf-to-oscal-sar: failed to parse HDF JSON: %w", err)
	}

	if hdfResults.Baselines == nil {
		return nil, fmt.Errorf("hdf-to-oscal-sar: invalid HDF structure: missing baselines field")
	}

	doc := buildOSCALDocument(&hdfResults)

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("hdf-to-oscal-sar: failed to serialize OSCAL output: %w", err)
	}

	return output, nil
}

// oscalSARDocument is the root wrapper for the output JSON.
type oscalSARDocument struct {
	AssessmentResults oscal.AssessmentResults `json:"assessment-results"`
}

// buildOSCALDocument constructs the full OSCAL assessment-results document from HDF results.
func buildOSCALDocument(hdfResults *hdf.HDFResults) *oscalSARDocument {
	now := time.Now().UTC().Format(time.RFC3339)
	if hdfResults.Timestamp != nil {
		now = hdfResults.Timestamp.Format(time.RFC3339)
	}

	// Define the assessment tool once for the whole document and reference its
	// single UUID from every characterization origin, so each actor-uuid resolves
	// to a party defined in the same document (OSCAL referential integrity, which
	// the JSON schema alone does not enforce). Sourced from the HDF tool identity.
	toolActorUUID := oscal.GenerateUUID()
	metadata := oscal.Metadata{
		Title:        "HDF Assessment Results Export",
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: oscal.OscalVersion,
		Parties: []oscal.Party{
			{UUID: toolActorUUID, Type: "organization", Name: toolPartyName(hdfResults)},
		},
	}

	// Build import-ap reference
	var importAP *oscal.ImportAP
	if hdfResults.PlanRef != nil && *hdfResults.PlanRef != "" {
		importAP = &oscal.ImportAP{Href: *hdfResults.PlanRef}
	} else {
		importAP = &oscal.ImportAP{Href: "#"}
	}

	// Assessed-asset identity: the top-level components[] become the subjects
	// attached to every observation. Built once so all observations share the
	// same subject identity (and subject-uuid) for a given component.
	subjects := buildSubjects(hdfResults.Components)

	// Build results from baselines, collecting the back-matter resources
	// (embedded check source code) their findings link to.
	results := make([]oscal.Result, 0, len(hdfResults.Baselines))
	var resources []oscal.Resource
	for i := range hdfResults.Baselines {
		result, res := baselineToResult(&hdfResults.Baselines[i], now, toolActorUUID, subjects)
		results = append(results, result)
		resources = append(resources, res...)
	}

	var backMatter *oscal.BackMatter
	if len(resources) > 0 {
		backMatter = &oscal.BackMatter{Resources: resources}
	}

	return &oscalSARDocument{
		AssessmentResults: oscal.AssessmentResults{
			UUID:       oscal.GenerateUUID(),
			Metadata:   metadata,
			ImportAP:   importAP,
			Results:    results,
			BackMatter: backMatter,
		},
	}
}

// toolPartyName derives a human-readable assessment-tool label from the HDF
// document's tool/generator identity, falling back when neither is present.
func toolPartyName(r *hdf.HDFResults) string {
	if r.Tool != nil && r.Tool.Name != nil && *r.Tool.Name != "" {
		if r.Tool.Version != nil && *r.Tool.Version != "" {
			return *r.Tool.Name + " " + *r.Tool.Version
		}
		return *r.Tool.Name
	}
	if r.Generator != nil && r.Generator.Name != "" {
		if r.Generator.Version != "" {
			return r.Generator.Name + " " + r.Generator.Version
		}
		return r.Generator.Name
	}
	return "HDF Assessment Tool"
}

// earliestResultTime returns the earliest non-zero startTime across the results.
func earliestResultTime(results []hdf.RequirementResult) time.Time {
	var earliest time.Time
	for i := range results {
		start := results[i].StartTime
		if start.IsZero() {
			continue
		}
		if earliest.IsZero() || start.Before(earliest) {
			earliest = start
		}
	}
	return earliest
}

// formatAssessmentTime renders an assessment time, falling back when HDF carries
// none. OSCAL requires result.start and observation.collected, so a fallback is
// always needed — but it must never be the default when a real time exists.
func formatAssessmentTime(t time.Time, fallback string) string {
	if t.IsZero() {
		return fallback
	}
	return t.UTC().Format(time.RFC3339)
}

// assessmentStart returns when the assessment actually ran: the earliest
// requirement-result startTime in the baseline. OSCAL result.start means the
// assessment time, so the document timestamp (when the HDF file was produced)
// must not be used for it.
func assessmentStart(baseline *hdf.EvaluatedBaseline, fallback string) string {
	var earliest time.Time
	for i := range baseline.Requirements {
		reqEarliest := earliestResultTime(baseline.Requirements[i].Results)
		if reqEarliest.IsZero() {
			continue
		}
		if earliest.IsZero() || reqEarliest.Before(earliest) {
			earliest = reqEarliest
		}
	}
	return formatAssessmentTime(earliest, fallback)
}

// baselineToResult converts a single EvaluatedBaseline to an OSCAL Result plus
// any back-matter resources (embedded check source code) its findings link to.
func baselineToResult(baseline *hdf.EvaluatedBaseline, timestamp string, toolActorUUID string, subjects []oscal.SubjectRef) (oscal.Result, []oscal.Resource) {
	title := baseline.Name
	if baseline.Title != nil && *baseline.Title != "" {
		title = *baseline.Title
	}

	description := "Converted from HDF results"
	if baseline.Description != nil && *baseline.Description != "" {
		description = *baseline.Description
	}

	// baseline.version has no first-class SAR home; carry it as a result prop.
	var resultProps []oscal.Property
	if baseline.Version != nil && *baseline.Version != "" {
		resultProps = append(resultProps, oscal.Property{Name: "baseline-version", Value: *baseline.Version})
	}

	var findings []oscal.Finding
	var observations []oscal.Observation
	var risks []oscal.Risk
	var resources []oscal.Resource

	// OSCAL requires result.reviewed-controls: the set of controls assessed.
	// Populate it from the control each requirement targets (deduped).
	var includeControls []oscal.SelectControl
	seenControl := make(map[string]bool)

	for i := range baseline.Requirements {
		req := &baseline.Requirements[i]
		f, obs, rsk, res := requirementToFindingSet(req, timestamp, toolActorUUID, subjects)
		findings = append(findings, f)
		if obs != nil {
			observations = append(observations, *obs)
		}
		if rsk != nil {
			risks = append(risks, *rsk)
		}
		if res != nil {
			resources = append(resources, *res)
		}
		if cid := oscal.NistTagToControlID(req.ID); cid != "" && !seenControl[cid] {
			seenControl[cid] = true
			includeControls = append(includeControls, oscal.SelectControl{ControlID: cid})
		}
	}

	return oscal.Result{
		UUID:             oscal.GenerateUUID(),
		Title:            title,
		Description:      description,
		Start:            assessmentStart(baseline, timestamp),
		Props:            resultProps,
		ReviewedControls: reviewedControls(includeControls),
		Findings:         findings,
		Observations:     observations,
		Risks:            risks,
	}, resources
}

// buildSubjects turns the top-level HDF components[] into OSCAL assessment
// subjects. Each component's UUID (componentId when present, otherwise a fresh
// one) identifies the subject; the HDF component type is a valid OSCAL subject
// type token and its name becomes the subject title.
func buildSubjects(components []hdf.Component) []oscal.SubjectRef {
	if len(components) == 0 {
		return nil
	}
	subjects := make([]oscal.SubjectRef, 0, len(components))
	for i := range components {
		c := &components[i]
		uid := oscal.GenerateUUID()
		if c.ComponentID != nil && *c.ComponentID != "" {
			uid = *c.ComponentID
		}
		subjects = append(subjects, oscal.SubjectRef{
			SubjectUUID: uid,
			Type:        string(c.Type),
			Title:       c.Name,
		})
	}
	return subjects
}

// reviewedControls builds the OSCAL reviewed-controls object from the assessed
// control IDs. OSCAL requires reviewed-controls on every result; when a baseline
// carries no identifiable controls, an empty control-selection still satisfies
// the schema (control-selection has no required members).
func reviewedControls(includeControls []oscal.SelectControl) *oscal.ReviewedControls {
	return &oscal.ReviewedControls{
		ControlSelections: []oscal.ControlSelection{
			{IncludeControls: includeControls},
		},
	}
}

// requirementToFindingSet converts an EvaluatedRequirement into a Finding,
// optional Observation, and optional Risk.
// descriptionByLabel returns the data of the first description matching a label, or "".
func descriptionByLabel(descriptions []hdf.Description, label string) string {
	for _, d := range descriptions {
		if d.Label == label {
			return d.Data
		}
	}
	return ""
}

func requirementToFindingSet(req *hdf.EvaluatedRequirement, timestamp string, toolActorUUID string, subjects []oscal.SubjectRef) (oscal.Finding, *oscal.Observation, *oscal.Risk, *oscal.Resource) {
	controlID := oscal.NistTagToControlID(req.ID)

	// Determine the finding state from the effective (post-override) status when
	// present, falling back to the raw worst-wins result aggregation. This makes
	// a waived / false-positive / risk-adjusted requirement report its assessed
	// posture rather than its raw result. The raw result status stays verbatim in
	// the observation description.
	state, reason := effectiveState(req)

	// Build finding description from requirement descriptions
	findingDesc := extractDefaultDescription(req.Descriptions)

	// Build props from control mappings (nist/cci), non-default descriptions
	// (check/fix/rationale), and v3.2 classification fields. OSCAL prop values
	// are StringDatatype (no newlines, no edge whitespace), so prose-capable
	// fields emit a single-line preview as the value and carry the full text in
	// the prop's own remarks (markup-multiline).
	var props []oscal.Property
	// OSCAL prop values must be non-empty strings, so skip any empty value
	// (e.g. an empty source `code`) rather than emitting a schema-invalid value: "".
	addProp := func(name, value string) {
		if value != "" {
			props = append(props, oscal.Property{Name: name, Value: value})
		}
	}
	addProseProp := func(name, text string) {
		preview := previewLine(text)
		if preview == "" {
			return
		}
		p := oscal.Property{Name: name, Value: preview}
		if preview != text {
			p.Remarks = text
		}
		props = append(props, p)
	}
	pushTagValues := func(key string) {
		if raw, ok := req.Tags[key]; ok {
			if arr, ok := raw.([]interface{}); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						addProp(key, s)
					}
				}
			}
		}
	}
	pushTagValues("nist")
	pushTagValues("cci")
	addProseProp("check", descriptionByLabel(req.Descriptions, "check"))
	addProseProp("rationale", descriptionByLabel(req.Descriptions, "rationale"))
	// fix text's OSCAL home is risk.remediations (built below when impact > 0,
	// the reverse importer's read path). Only an impact-0 requirement, which
	// emits no risk, carries it as a finding prop instead.
	if req.Impact <= 0 {
		addProseProp("fix", descriptionByLabel(req.Descriptions, "fix"))
	}
	if req.ControlType != nil {
		addProp("control-type", string(*req.ControlType))
	}
	if req.VerificationMethod != nil {
		addProp("verification-method", string(*req.VerificationMethod))
	}
	if req.Applicability != nil {
		addProp("applicability", string(*req.Applicability))
	}

	// Vulnerability enrichment (CWE / EPSS / KEV / CVSS) has no first-class SAR
	// home; surface it as finding props so it is not silently dropped.
	for _, cwe := range req.Cwe {
		addProp("cwe", cwe)
	}
	if req.Epss != nil {
		addProp("epss-score", strconv.FormatFloat(req.Epss.Score, 'f', -1, 64))
		addProp("epss-percentile", strconv.FormatFloat(req.Epss.Percentile, 'f', -1, 64))
	}
	if req.Kev != nil && req.Kev.InKev {
		addProp("kev", "true")
		if req.Kev.DueDate != nil {
			addProp("kev-due-date", *req.Kev.DueDate)
		}
	}
	for i := range req.Cvss {
		c := &req.Cvss[i]
		if c.BaseScore != nil {
			addProp("cvss-base-score", strconv.FormatFloat(*c.BaseScore, 'f', -1, 64))
		}
		if c.BaseVector != nil {
			addProp("cvss-base-vector", *c.BaseVector)
		}
	}

	// refs: url/uri -> OSCAL links; a plain string ref -> prop (not a valid href).
	// url/uri refs are additionally emitted as observation relevant-evidence
	// (below) so they round-trip through the reverse SAR importer, which reads
	// refs only from relevant-evidence hrefs, not finding.links.
	var links []oscal.Link
	for _, r := range req.Refs {
		switch {
		case r.URL != nil:
			links = append(links, oscal.Link{Href: *r.URL, Rel: "reference"})
		case r.URI != nil:
			links = append(links, oscal.Link{Href: *r.URI, Rel: "reference"})
		case r.Ref != nil && r.Ref.String != nil:
			addProseProp("reference", *r.Ref.String)
		}
	}

	// externalReferences (advisory / STIX / definition-source URIs) share the
	// finding.links home already used for refs.
	for i := range req.ExternalReferences {
		er := &req.ExternalReferences[i]
		if er.Href != nil && *er.Href != "" {
			links = append(links, oscal.Link{Href: *er.Href, Rel: "reference"})
		}
	}

	title := req.ID
	if req.Title != nil && *req.Title != "" {
		title = *req.Title
	}

	// Source code is an artifact with a media type, not a StringDatatype prop:
	// embed it as a back-matter resource and point at it with a rel="code" link.
	var codeResource *oscal.Resource
	if req.Code != nil && strings.TrimSpace(*req.Code) != "" {
		codeResource = &oscal.Resource{
			UUID:  oscal.GenerateUUID(),
			Title: "Check source code for " + req.ID,
			Base64: &oscal.Base64{
				Value:     base64.StdEncoding.EncodeToString([]byte(*req.Code)),
				MediaType: "text/plain",
			},
		}
		links = append(links, oscal.Link{Href: "#" + codeResource.UUID, Rel: "code"})
	}

	// OSCAL requires a non-empty finding description; fall back to the title
	// when the requirement carries no description of its own.
	if findingDesc == "" {
		findingDesc = title
	}

	finding := oscal.Finding{
		UUID:        oscal.GenerateUUID(),
		Title:       title,
		Description: findingDesc,
		Props:       props,
		Links:       links,
		Target: oscal.FindingTarget{
			Type:     "objective-id",
			TargetID: controlID,
			Status: oscal.TargetStatus{
				State:  state,
				Reason: reason,
				// Governing disposition + most-recent override provenance so the
				// reason the requirement is in this state is not lost.
				Remarks: overrideRemarks(req),
			},
		},
	}

	// Build observation from requirement results
	var observation *oscal.Observation
	if len(req.Results) > 0 {
		obsUUID := oscal.GenerateUUID()
		obsDesc := buildObservationDescription(req.Results)
		observation = &oscal.Observation{
			UUID:        obsUUID,
			Description: obsDesc,
			Methods:     []string{"TEST"},
			// When the evidence was gathered — the scan time for this requirement,
			// not when the file was converted.
			Collected: formatAssessmentTime(earliestResultTime(req.Results), timestamp),
			// Assessed-asset identity (top-level components) and the requirement's
			// refs / evidence / source location, in the homes the reverse importer
			// reads back.
			Subjects:         subjects,
			RelevantEvidence: buildRelevantEvidence(req),
		}
		finding.RelatedObservations = []oscal.RelatedRef{
			{ObservationUUID: obsUUID},
		}
	}

	// Build risk from impact
	var risk *oscal.Risk
	if req.Impact > 0 {
		riskUUID := oscal.GenerateUUID()
		severity := oscal.ImpactToSeverity(req.Impact)
		// An explicit severity that disagrees with the impact-derived band drives
		// the characterization facet (the channel the reverse importer reads).
		facetValue := severity
		if req.Severity != nil {
			if v := severityToFacetValue(*req.Severity); v != "" {
				facetValue = v
			}
		}
		impactText := fmt.Sprintf("Impact: %.1f (%s)", req.Impact, severity)
		risk = &oscal.Risk{
			UUID:  riskUUID,
			Title: fmt.Sprintf("Risk for %s", req.ID),
			// OSCAL requires both description and statement on a risk.
			Description: impactText,
			Statement:   impactText,
			Status:      riskStatusFromState(state),
			Characterizations: []oscal.Characterization{
				{
					// OSCAL requires characterization.origin. Reference the single
					// document-level tool party so the actor-uuid resolves to a defined party.
					Origin: &oscal.Origin{
						Actors: []oscal.Actor{
							{Type: "party", ActorID: toolActorUUID},
						},
					},
					Facets: []oscal.Facet{
						{
							Name:   "impact",
							System: "https://fedramp.gov",
							Value:  facetValue,
						},
					},
				},
			},
			Remediations: buildRemediations(req),
			Deadline:     riskDeadline(req),
		}
		finding.RelatedRisks = []oscal.RelatedRef{
			{RiskUUID: riskUUID},
		}
	}

	return finding, observation, risk, codeResource
}

// previewLine reduces prose to a single line legal as an OSCAL StringDatatype
// prop value: the first non-empty line, trimmed, truncated to 120 runes.
func previewLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		const maxRunes = 120
		runes := []rune(line)
		if len(runes) > maxRunes {
			line = strings.TrimSpace(string(runes[:maxRunes-3])) + "..."
		}
		return line
	}
	return ""
}

// effectiveState derives the OSCAL finding target state/reason from the
// requirement's effectiveStatus when present, otherwise from the aggregated raw
// result status.
func effectiveState(req *hdf.EvaluatedRequirement) (state string, reason string) {
	if req.EffectiveStatus != nil {
		return oscalStateFromStatus(*req.EffectiveStatus)
	}
	return aggregateStatus(req.Results)
}

// oscalStateFromStatus maps a single HDF result status to an OSCAL finding
// target state and reason, mirroring aggregateStatus for a single value.
func oscalStateFromStatus(status hdf.ResultStatus) (state string, reason string) {
	switch status {
	case hdf.Passed:
		return "satisfied", ""
	case hdf.NotApplicable:
		return "not-satisfied", "not-applicable"
	case hdf.NotReviewed:
		return "not-satisfied", "other"
	default:
		return "not-satisfied", ""
	}
}

// overrideRemarks renders the governing disposition and the most-recent status
// override's provenance into finding.target.status.remarks. Returns "" when the
// requirement carries no disposition or overrides.
func overrideRemarks(req *hdf.EvaluatedRequirement) string {
	var parts []string
	if req.Disposition != nil {
		parts = append(parts, "Disposition: "+string(*req.Disposition))
	}
	if len(req.StatusOverrides) > 0 {
		o := &req.StatusOverrides[0] // most-recent first per schema convention
		parts = append(parts, "Override: "+string(o.Type))
		if o.Reason != "" {
			parts = append(parts, "Reason: "+o.Reason)
		}
		if o.AppliedBy.Identifier != "" {
			parts = append(parts, "Applied by: "+o.AppliedBy.Identifier)
		}
		if !o.AppliedAt.IsZero() {
			parts = append(parts, "Applied at: "+o.AppliedAt.UTC().Format(time.RFC3339))
		}
		if !o.ExpiresAt.IsZero() {
			parts = append(parts, "Expires at: "+o.ExpiresAt.UTC().Format(time.RFC3339))
		}
	}
	return strings.Join(parts, "; ")
}

// buildRelevantEvidence collects the requirement's refs, evidence, and source
// location into OSCAL observation relevant-evidence, the home the reverse SAR
// importer reads back into HDF refs (via href) and evidence (via description).
func buildRelevantEvidence(req *hdf.EvaluatedRequirement) []oscal.RelevantEvidence {
	var ev []oscal.RelevantEvidence
	for _, r := range req.Refs {
		switch {
		case r.URL != nil && *r.URL != "":
			ev = append(ev, oscal.RelevantEvidence{Href: *r.URL})
		case r.URI != nil && *r.URI != "":
			ev = append(ev, oscal.RelevantEvidence{Href: *r.URI})
		}
	}
	for i := range req.Evidence {
		e := &req.Evidence[i]
		re := oscal.RelevantEvidence{}
		if e.Description != nil {
			re.Description = *e.Description
		}
		if e.Type == hdf.URL && e.Data != "" {
			re.Href = e.Data
		}
		if re.Href != "" || re.Description != "" {
			ev = append(ev, re)
		}
	}
	if req.SourceLocation != nil {
		if loc := sourceLocationText(req.SourceLocation); loc != "" {
			ev = append(ev, oscal.RelevantEvidence{Description: "Source location: " + loc})
		}
	}
	return ev
}

// sourceLocationText renders a source location as "ref:line", degrading to
// whichever field is present. Returns "" when neither is set.
func sourceLocationText(loc *hdf.SourceLocation) string {
	ref := ""
	if loc.Ref != nil {
		ref = *loc.Ref
	}
	if loc.Line != nil {
		if ref != "" {
			return fmt.Sprintf("%s:%d", ref, int(*loc.Line))
		}
		return fmt.Sprintf("line %d", int(*loc.Line))
	}
	return ref
}

// severityToFacetValue maps an explicit HDF severity to the OSCAL risk facet
// value vocabulary the reverse importer recognizes.
func severityToFacetValue(s hdf.Severity) string {
	switch s {
	case hdf.SeverityCritical:
		return "critical"
	case hdf.SeverityHigh:
		return "high"
	case hdf.SeverityMedium:
		return "moderate"
	case hdf.SeverityLow:
		return "low"
	case hdf.Informational:
		return "info"
	default:
		return ""
	}
}

// buildRemediations turns the requirement's fix description and any governing
// risk-acceptance override into OSCAL risk remediations, the home the reverse
// importer reads back as the HDF remediation description.
func buildRemediations(req *hdf.EvaluatedRequirement) []oscal.Remediation {
	var rems []oscal.Remediation
	if fix := descriptionByLabel(req.Descriptions, "fix"); fix != "" {
		rems = append(rems, oscal.Remediation{
			UUID:        oscal.GenerateUUID(),
			Lifecycle:   "recommendation",
			Title:       "Recommended fix",
			Description: fix,
		})
	}
	if req.Disposition != nil && len(req.StatusOverrides) > 0 {
		o := &req.StatusOverrides[0]
		desc := o.Reason
		if desc == "" {
			desc = "Risk accepted via " + string(*req.Disposition)
		}
		rems = append(rems, oscal.Remediation{
			UUID:        oscal.GenerateUUID(),
			Lifecycle:   "accepted",
			Title:       string(*req.Disposition),
			Description: desc,
		})
	}
	return rems
}

// riskDeadline surfaces a governing risk-acceptance override's expiry as the
// risk deadline (the field the OSCAL POA&M importer reads back). Returns "" when
// no override expiry applies.
func riskDeadline(req *hdf.EvaluatedRequirement) string {
	if len(req.StatusOverrides) > 0 {
		if o := &req.StatusOverrides[0]; !o.ExpiresAt.IsZero() {
			return o.ExpiresAt.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// aggregateStatus determines the overall finding status from requirement results.
// If any result is failed or error, the finding is not-satisfied.
// If all are passed, the finding is satisfied.
// Otherwise, not-satisfied with a reason.
func aggregateStatus(results []hdf.RequirementResult) (state string, reason string) {
	if len(results) == 0 {
		return "not-satisfied", "other"
	}

	hasFailed := false
	hasError := false
	hasNotReviewed := false
	hasNotApplicable := false
	allPassed := true

	for _, r := range results {
		switch r.Status {
		case hdf.Passed:
			// ok
		case hdf.Failed:
			hasFailed = true
			allPassed = false
		case hdf.Error:
			hasError = true
			allPassed = false
		case hdf.NotReviewed:
			hasNotReviewed = true
			allPassed = false
		case hdf.NotApplicable:
			hasNotApplicable = true
			allPassed = false
		default:
			allPassed = false
		}
	}

	if allPassed {
		return "satisfied", ""
	}
	if hasFailed || hasError {
		return "not-satisfied", ""
	}
	if hasNotReviewed {
		return "not-satisfied", "other"
	}
	if hasNotApplicable {
		return "not-satisfied", "not-applicable"
	}
	return "not-satisfied", ""
}

// extractDefaultDescription finds the "default" labeled description.
func extractDefaultDescription(descriptions []hdf.Description) string {
	for _, d := range descriptions {
		if d.Label == "default" {
			return d.Data
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Data
	}
	return ""
}

// buildObservationDescription concatenates result code descriptions and messages.
func buildObservationDescription(results []hdf.RequirementResult) string {
	var parts []string
	for _, r := range results {
		desc := fmt.Sprintf("[%s] %s", r.Status, r.CodeDesc)
		if r.Message != nil && *r.Message != "" {
			desc += ": " + *r.Message
		}
		parts = append(parts, desc)
	}
	if len(parts) == 0 {
		return "No observations recorded"
	}
	return strings.Join(parts, "\n")
}

// riskStatusFromState maps OSCAL finding state to risk status.
func riskStatusFromState(state string) string {
	if state == "satisfied" {
		return "closed"
	}
	return "open"
}
