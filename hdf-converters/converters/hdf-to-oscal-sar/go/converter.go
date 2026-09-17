// Package hdftooscalsar converts HDF Results to OSCAL Assessment Results (SAR) format.
//
// This is the reverse direction of the oscal-to-hdf SAR converter. It takes HDF
// Results JSON and produces an OSCAL 1.1.2 assessment-results JSON document.
package hdftooscalsar

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertHDFToOSCALSAR converts HDF Results JSON bytes to OSCAL Assessment
// Results JSON bytes. The converterVersion parameter is unused but present
// to conform to the RawConvertFn signature.
func ConvertHDFToOSCALSAR(input []byte, _ string) ([]byte, error) {
	var hdfResults hdf.HDFResults
	if err := shared.RequireHDFResultsTyped(input, "hdf-to-oscal-sar", &hdfResults); err != nil {
		return nil, err
	}

	// A converter-specific constraint the shared guard cannot express: the guard
	// checks top-level shape, not the full HDF schema, and it accepts an empty
	// baselines array because hdf-results puts no minItems on it. OSCAL Assessment
	// Results, by contrast, requires results with minItems 1, and one result is
	// emitted per baseline — so an assessment that evaluated nothing has no valid
	// OSCAL representation. Emitting "results": [] would exit 0 with a document
	// the target schema rejects.
	//
	// Whether hdf-results should itself carry minItems 1 on baselines, as every
	// sibling document schema except hdf-comparison does on its required
	// collections, is an open schema question. If it gains one, RequireHDFResults
	// should switch from its nil check to the len == 0 check RequireHDFAmendments
	// already uses, and this check becomes redundant.
	if len(hdfResults.Baselines) == 0 {
		return nil, fmt.Errorf("hdf-to-oscal-sar: cannot represent an assessment with no evaluated baselines as OSCAL Assessment Results, which requires at least one result")
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
	if baseline.Version != nil {
		resultProps = oscal.AppendVocabularyProp(resultProps, "baseline-version", *baseline.Version)
	}

	var findings []oscal.Finding
	var observations []oscal.Observation
	var risks []oscal.Risk
	var resources []oscal.Resource

	// OSCAL requires result.reviewed-controls: the set of controls assessed.
	// Populate it from the control each requirement targets (deduped).
	var includeControls []oscal.SelectControl
	controlIndex := make(map[string]int)

	for i := range baseline.Requirements {
		req := &baseline.Requirements[i]

		// A finding is a claim about a specific control, and OSCAL types
		// target-id as a token — an empty one fails the pattern outright. HDF
		// requires an id on a requirement, so reaching this is already invalid
		// input, but emitting the finding anyway would produce a document the
		// target schema rejects. The finding is dropped rather than carrying a
		// fabricated identifier the source never had. Compute the control id once
		// so the guard and the reviewed-controls encoding below cannot drift.
		nistID, statementID := oscal.NistTagToControlRef(req.ID)
		if nistID == "" {
			continue
		}

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
		// Declares the control behind the finding's target (narrowed to its
		// statement when the target is one): a finding whose control is absent
		// from this list would validate while claiming to assess something the
		// result never declares reviewing.
		if cid := oscal.OSCALToken(nistID); cid != "" {
			includeControls = selectControl(includeControls, controlIndex, cid, statementID)
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

// selectControl adds a control, or one statement of it, to the reviewed-controls
// selection, one entry per control. A control selected whole carries no
// statement-ids, because listing any would narrow the selection to them.
func selectControl(controls []oscal.SelectControl, index map[string]int, controlID, statementID string) []oscal.SelectControl {
	i, seen := index[controlID]
	if !seen {
		index[controlID] = len(controls)
		selection := oscal.SelectControl{ControlID: controlID}
		if statementID != "" {
			selection.StatementIDs = []string{statementID}
		}
		return append(controls, selection)
	}
	selection := &controls[i]
	if selection.StatementIDs == nil {
		return controls
	}
	if statementID == "" {
		selection.StatementIDs = nil
	} else if !slices.Contains(selection.StatementIDs, statementID) {
		selection.StatementIDs = append(selection.StatementIDs, statementID)
	}
	return controls
}

// buildSubjects turns the top-level HDF components[] into OSCAL assessment
// subjects. Each component's UUID (componentId when present, otherwise a fresh
// one) identifies the subject; the HDF component type is a valid OSCAL subject
// type token and its name becomes the subject title.
//
// A component with no type is skipped rather than given one. OSCAL requires both
// subject-uuid and type on a subject-reference, so the type cannot simply be
// omitted, and hdf-results defines no default component type to fall back on —
// inventing one would assert a component type the source never stated.
func buildSubjects(components []hdf.Component) []oscal.SubjectRef {
	if len(components) == 0 {
		return nil
	}
	subjects := make([]oscal.SubjectRef, 0, len(components))
	for i := range components {
		c := &components[i]
		if oscal.OSCALString(string(c.Type)) == "" {
			continue
		}
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

// noIdentifiableControlsRemark accompanies the include-all selection of a result
// whose baseline names no control, so the selection is not read as a claim.
const noIdentifiableControlsRemark = "No controls were identifiable in the assessed input, so none is listed individually. OSCAL requires a control selection; include-all is emitted to satisfy it and does not assert that any control was assessed."

// reviewedControls builds the OSCAL reviewed-controls object from the assessed
// control IDs. OSCAL requires reviewed-controls on every result, and from 1.2.0
// every control-selection must carry include-all or include-controls, so a
// baseline with no identifiable controls (a clean scan) selects include-all with
// a remark stating that no control was assessed. 1.1.2 accepts the same shape.
func reviewedControls(includeControls []oscal.SelectControl) *oscal.ReviewedControls {
	selection := oscal.ControlSelection{IncludeControls: includeControls}
	if len(includeControls) == 0 {
		selection = oscal.ControlSelection{IncludeAll: &oscal.IncludeAll{}, Remarks: noIdentifiableControlsRemark}
	}
	return &oscal.ReviewedControls{
		ControlSelections: []oscal.ControlSelection{selection},
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
	// OSCAL types target-id as a token, and a requirement id is only token-shaped
	// when the source tool happens to number its rules that way. The source id is
	// recorded exactly in the hdf-requirement-id prop below, so the encoding does
	// not lose which requirement this came from even though it is not injective.
	controlID, statementID := oscal.NistTagToControlRef(req.ID)
	targetType, targetID := "objective-id", oscal.OSCALToken(controlID)
	if statementID != "" {
		targetType, targetID = "statement-id", statementID
	}

	// Determine the finding state from the effective (post-override) status when
	// present, falling back to the raw worst-wins result aggregation. This makes
	// a waived / false-positive / risk-adjusted requirement report its assessed
	// posture rather than its raw result. The raw result status stays verbatim in
	// the observation description.
	state, reason := effectiveState(req)

	// Build finding description from requirement descriptions
	findingDesc := extractDefaultDescription(req.Descriptions)

	// The source requirement id. target-id carries an encoded form, because OSCAL
	// constrains it to a token, so without this the identifier the source tool
	// reported would be unrecoverable — the encoding is not injective.
	//
	// Then control mappings (nist/cci) and v3.2 classification fields. Every prop
	// goes through the vocabulary helper, which namespaces it and keeps the exact
	// value in remarks when OSCAL's single-line StringDatatype cannot hold it.
	props := oscal.AppendVocabularyProp(nil, "hdf-requirement-id", req.ID)
	addProp := func(name, value string) {
		props = oscal.AppendVocabularyProp(props, name, value)
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
			addProp("reference", *r.Ref.String)
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
			Props: oscal.AppendVocabularyProp(nil, "type", "evidence"),
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
			Type:     targetType,
			TargetID: targetID,
			// The assessor's conclusion about the objective: rationale's OSCAL home.
			Description: descriptionByLabel(req.Descriptions, "rationale"),
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
	} else {
		warnUncarriedProse(req)
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
		impactText := fmt.Sprintf("Impact: %s (%s)", hdfutil.FormatFixed(req.Impact, 1), severity)
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

// previewLine reduces prose to a single line for an OSCAL single-line field: the
// first non-empty line, trimmed, truncated to 120 runes.
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

// effectiveState derives the OSCAL finding target state/reason via the
// canonical effective-status ladder — the stored effectiveStatus field is
// never read (output cache; see status-determination.md).
func effectiveState(req *hdf.EvaluatedRequirement) (state string, reason string) {
	resolved := hdf.ResultStatus(hdfutil.ComputeEffectiveStatus(shared.RequirementStatusInput(*req), time.Time{}))
	return oscalStateFromStatus(resolved)
}

// oscalStateFromStatus maps a single HDF result status to an OSCAL finding
// target state and reason.
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

// buildRelevantEvidence collects the requirement's refs, evidence and source
// location, then its check (and impact-0 fix) prose, into OSCAL observation
// relevant-evidence, the home the reverse SAR importer reads back into HDF
// refs (via href), evidence (via description) and check/fix (via
// description-label).
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
	// Labelled prose follows the entries above so their index positions are stable.
	for _, label := range observationProseLabels(req) {
		text := descriptionByLabel(req.Descriptions, label)
		ev = append(ev, oscal.RelevantEvidence{
			Description: previewLine(text),
			Props:       []oscal.Property{oscal.DescriptionLabelProp(label)},
			Remarks:     text,
		})
	}
	return ev
}

// observationProseLabels lists the description labels whose text the
// requirement's observation carries as labelled evidence: check, and fix when
// impact is 0 (otherwise fix's home is the risk remediation). A description
// with no preview text carries nothing.
func observationProseLabels(req *hdf.EvaluatedRequirement) []string {
	candidates := []string{"check"}
	if req.Impact <= 0 {
		candidates = append(candidates, "fix")
	}
	var labels []string
	for _, label := range candidates {
		if previewLine(descriptionByLabel(req.Descriptions, label)) != "" {
			labels = append(labels, label)
		}
	}
	return labels
}

// warnUncarriedProse reports observation-scoped prose lost because a
// requirement with no results emits no observation.
func warnUncarriedProse(req *hdf.EvaluatedRequirement) {
	labels := observationProseLabels(req)
	switch len(labels) {
	case 0:
		return
	case 1:
		log.Printf("WARNING: hdf-to-oscal-sar: requirement %q has no results, so no observation holds its %s description; it was not carried", req.ID, labels[0])
	default:
		log.Printf("WARNING: hdf-to-oscal-sar: requirement %q has no results, so no observation holds its %s descriptions; they were not carried", req.ID, strings.Join(labels, " and "))
	}
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
	return shared.OSCALSeverityFromHDF(string(s))
}

// buildRemediations turns the requirement's fix description and any governing
// risk-acceptance override into OSCAL risk remediations. The reverse importer
// reads the labelled fix back as the HDF fix description and the rest as the
// remediation description.
func buildRemediations(req *hdf.EvaluatedRequirement) []oscal.Remediation {
	var rems []oscal.Remediation
	if fix := descriptionByLabel(req.Descriptions, "fix"); fix != "" {
		rems = append(rems, oscal.Remediation{
			UUID:        oscal.GenerateUUID(),
			Lifecycle:   "recommendation",
			Title:       "Recommended fix",
			Description: fix,
			Props:       []oscal.Property{oscal.DescriptionLabelProp("fix")},
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

// extractDefaultDescription returns the "default"-labeled description, or "".
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
