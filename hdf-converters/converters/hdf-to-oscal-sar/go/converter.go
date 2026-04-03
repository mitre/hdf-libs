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

	oscal "github.com/mitre/hdf-converters/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
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
	if err := json.Unmarshal(input, &hdfResults); err != nil {
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

	// Build metadata
	metadata := oscal.Metadata{
		Title:        "HDF Assessment Results Export",
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: oscal.OscalVersion,
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
		result := baselineToResult(&hdfResults.Baselines[i], now)
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

// baselineToResult converts a single EvaluatedBaseline to an OSCAL Result.
func baselineToResult(baseline *hdf.EvaluatedBaseline, timestamp string) oscal.Result {
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

	for i := range baseline.Requirements {
		req := &baseline.Requirements[i]
		f, obs, rsk := requirementToFindingSet(req, timestamp)
		findings = append(findings, f)
		if obs != nil {
			observations = append(observations, *obs)
		}
		if rsk != nil {
			risks = append(risks, *rsk)
		}
	}

	return oscal.Result{
		UUID:         oscal.GenerateUUID(),
		Title:        title,
		Description:  description,
		Start:        timestamp,
		Findings:     findings,
		Observations: observations,
		Risks:        risks,
	}
}

// requirementToFindingSet converts an EvaluatedRequirement into a Finding,
// optional Observation, and optional Risk.
func requirementToFindingSet(req *hdf.EvaluatedRequirement, timestamp string) (oscal.Finding, *oscal.Observation, *oscal.Risk) {
	controlID := oscal.NistTagToControlID(req.ID)

	// Determine overall status from results
	state, reason := aggregateStatus(req.Results)

	// Build finding description from requirement descriptions
	findingDesc := extractDefaultDescription(req.Descriptions)

	// Build props from NIST tags
	var props []oscal.Property
	if req.Tags != nil {
		if nistRaw, ok := req.Tags["nist"]; ok {
			if nistArr, ok := nistRaw.([]interface{}); ok {
				for _, v := range nistArr {
					if s, ok := v.(string); ok {
						props = append(props, oscal.Property{
							Name:  "nist",
							Value: s,
						})
					}
				}
			}
		}
	}

	title := req.ID
	if req.Title != nil && *req.Title != "" {
		title = *req.Title
	}

	finding := oscal.Finding{
		UUID:        oscal.GenerateUUID(),
		Title:       title,
		Description: findingDesc,
		Props:       props,
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
			Collected:   timestamp,
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
		risk = &oscal.Risk{
			UUID:        riskUUID,
			Title:       fmt.Sprintf("Risk for %s", req.ID),
			Description: fmt.Sprintf("Impact: %.1f (%s)", req.Impact, severity),
			Status:      riskStatusFromState(state),
			Characterizations: []oscal.Characterization{
				{
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
