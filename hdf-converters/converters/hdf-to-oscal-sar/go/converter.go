// Package hdftooscalsar converts HDF Results to OSCAL Assessment Results (SAR) format.
//
// This is the reverse direction of the oscal-to-hdf SAR converter. It takes HDF
// Results JSON and produces an OSCAL 1.1.2 assessment-results JSON document.
package hdftooscalsar

import (
	"encoding/json"
	"fmt"
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

	// Build results from baselines
	results := make([]oscal.Result, 0, len(hdfResults.Baselines))
	for i := range hdfResults.Baselines {
		result := baselineToResult(&hdfResults.Baselines[i], now, toolActorUUID)
		results = append(results, result)
	}

	return &oscalSARDocument{
		AssessmentResults: oscal.AssessmentResults{
			UUID:     oscal.GenerateUUID(),
			Metadata: metadata,
			ImportAP: importAP,
			Results:  results,
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

// baselineToResult converts a single EvaluatedBaseline to an OSCAL Result.
func baselineToResult(baseline *hdf.EvaluatedBaseline, timestamp string, toolActorUUID string) oscal.Result {
	title := baseline.Name
	if baseline.Title != nil && *baseline.Title != "" {
		title = *baseline.Title
	}

	description := "Converted from HDF results"
	if baseline.Description != nil && *baseline.Description != "" {
		description = *baseline.Description
	}

	var findings []oscal.Finding
	var observations []oscal.Observation
	var risks []oscal.Risk

	// OSCAL requires result.reviewed-controls: the set of controls assessed.
	// Populate it from the control each requirement targets (deduped).
	var includeControls []oscal.SelectControl
	seenControl := make(map[string]bool)

	for i := range baseline.Requirements {
		req := &baseline.Requirements[i]
		f, obs, rsk := requirementToFindingSet(req, timestamp, toolActorUUID)
		findings = append(findings, f)
		if obs != nil {
			observations = append(observations, *obs)
		}
		if rsk != nil {
			risks = append(risks, *rsk)
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
		ReviewedControls: reviewedControls(includeControls),
		Findings:         findings,
		Observations:     observations,
		Risks:            risks,
	}
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

func requirementToFindingSet(req *hdf.EvaluatedRequirement, timestamp string, toolActorUUID string) (oscal.Finding, *oscal.Observation, *oscal.Risk) {
	controlID := oscal.NistTagToControlID(req.ID)

	// Determine overall status from results
	state, reason := aggregateStatus(req.Results)

	// Build finding description from requirement descriptions
	findingDesc := extractDefaultDescription(req.Descriptions)

	// Build props from control mappings (nist/cci), code, non-default
	// descriptions (check/fix/rationale), and v3.2 classification fields.
	var props []oscal.Property
	// OSCAL prop values must be non-empty strings, so skip any empty value
	// (e.g. an empty source `code`) rather than emitting a schema-invalid value: "".
	addProp := func(name, value string) {
		if value != "" {
			props = append(props, oscal.Property{Name: name, Value: value})
		}
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
	if req.Code != nil {
		addProp("code", *req.Code)
	}
	for _, label := range []string{"check", "fix", "rationale"} {
		addProp(label, descriptionByLabel(req.Descriptions, label))
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

	// refs: url/uri -> OSCAL links; a plain string ref -> prop (not a valid href).
	var links []oscal.Link
	for _, r := range req.Refs {
		switch {
		case r.URL != nil:
			links = append(links, oscal.Link{Href: *r.URL, Rel: "reference"})
		case r.URI != nil:
			links = append(links, oscal.Link{Href: *r.URI, Rel: "reference"})
		case r.Ref != nil && r.Ref.String != nil:
			props = append(props, oscal.Property{Name: "reference", Value: *r.Ref.String})
		}
	}

	title := req.ID
	if req.Title != nil && *req.Title != "" {
		title = *req.Title
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
							Value:  severity,
						},
					},
				},
			},
		}
		finding.RelatedRisks = []oscal.RelatedRef{
			{RiskUUID: riskUUID},
		}
	}

	return finding, observation, risk
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
