package oscal

import (
	"log"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertAssessmentResultsToHDF converts an OSCAL Assessment Results (SAR)
// document to HDF Results. Each results[] entry becomes an EvaluatedBaseline,
// and each finding becomes an EvaluatedRequirement with pass/fail results.
func ConvertAssessmentResultsToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	doc, err := ParseOscalDocument(input, "assessment-results", "oscal-assessment-results")
	if err != nil {
		return nil, err
	}

	return sarToHDFResults(doc.AssessmentResults, input, converterVersion)
}

// sarToHDFResults converts a parsed AssessmentResults to HDFResults.
func sarToHDFResults(sar *AssessmentResults, rawInput []byte, converterVersion string) (*hdf.HDFResults, error) {
	meta := ExtractMetadata(sar.Metadata)

	// One conversion-time value, shared as the startTime fallback for any
	// finding whose OSCAL result lacks a usable start.
	scanTime := time.Now().UTC()

	baselines := make([]hdf.EvaluatedBaseline, 0, len(sar.Results))
	for i := range sar.Results {
		r := &sar.Results[i]
		if len(r.Findings) == 0 {
			title := r.Title
			if title == "" {
				title = r.UUID
			}
			log.Printf("WARNING: Skipping assessment result %q: no findings (empty result set)", title)
			continue
		}
		baseline := resultToEvaluatedBaseline(r, sar, rawInput, scanTime)
		baselines = append(baselines, baseline)
	}

	// Extract planRef from import-ap
	var planRef *string
	if sar.ImportAP != nil && sar.ImportAP.Href != "" {
		planRef = hdfutil.Ptr(sar.ImportAP.Href)
	}

	// Parse timestamp from metadata
	var timestamp *time.Time
	if meta.LastModified != "" {
		if t, err := time.Parse(time.RFC3339, meta.LastModified); err == nil {
			timestamp = &t
		}
	}

	result := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "oscal-assessment-results-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "OSCAL Assessment Results",
		ToolFormat:       "OSCAL",
		Baselines:        baselines,
		Timestamp:        timestamp,
	})

	result.PlanRef = planRef

	return result, nil
}

// resultToEvaluatedBaseline converts a single OSCAL Result to an HDF
// EvaluatedBaseline. Findings are grouped by control ID so that multiple
// findings for the same control produce multiple results on the same
// requirement.
func resultToEvaluatedBaseline(result *Result, sar *AssessmentResults, rawInput []byte, scanTime time.Time) hdf.EvaluatedBaseline {
	checksum := shared.InputChecksum(rawInput)
	integrity := shared.InputIntegrity(rawInput)

	// Build lookup maps for observations and risks
	obsMap := buildObservationMap(result.Observations)
	riskMap := buildRiskMap(result.Risks)

	// Group findings by control ID, preserving insertion order
	type controlFindings struct {
		controlID string
		findings  []*Finding
	}
	controlOrder := make([]string, 0)
	controlMap := make(map[string]*controlFindings)

	limitedFindings := shared.LimitSliceWithWarning(result.Findings, 0, "finding")
	for i := range limitedFindings {
		f := &limitedFindings[i]
		controlID := extractControlIDFromFinding(f)
		if existing, ok := controlMap[controlID]; ok {
			existing.findings = append(existing.findings, f)
		} else {
			controlOrder = append(controlOrder, controlID)
			controlMap[controlID] = &controlFindings{
				controlID: controlID,
				findings:  []*Finding{f},
			}
		}
	}

	// Build requirements in insertion order
	requirements := make([]hdf.EvaluatedRequirement, 0, len(controlOrder))
	for _, controlID := range controlOrder {
		cf := controlMap[controlID]
		req := findingsToEvaluatedRequirement(cf.controlID, cf.findings, obsMap, riskMap, result, scanTime)
		requirements = append(requirements, req)
	}

	// Derive baseline name
	name := sarBaselineName(result, sar)

	status := "loaded"
	baseline := hdf.EvaluatedBaseline{
		Name:            name,
		Title:           hdfutil.Ptr(result.Title),
		Status:          &status,
		Integrity:       integrity,
		ResultsChecksum: checksum,
		Requirements:    requirements,
	}

	if result.Description != "" {
		baseline.Description = hdfutil.Ptr(result.Description)
	}

	return baseline
}

// findingsToEvaluatedRequirement converts one or more findings for the same
// control ID into a single EvaluatedRequirement with multiple results.
func findingsToEvaluatedRequirement(
	controlID string,
	findings []*Finding,
	obsMap map[string]*Observation,
	riskMap map[string]*Risk,
	result *Result,
	scanTime time.Time,
) hdf.EvaluatedRequirement {
	nistTag := ControlIDToNistTag(controlID)

	// Use the first finding for title/description
	firstFinding := findings[0]
	title := firstFinding.Title
	if title == "" {
		title = nistTag
	}

	// Determine impact from related risks across all findings
	impact := sarFindingsImpact(findings, riskMap)

	// Build descriptions from findings and observations
	descriptions := sarBuildDescriptions(findings, obsMap)

	// Build results from each finding
	results := make([]hdf.RequirementResult, 0, len(findings))
	for _, f := range findings {
		reqResult := findingToRequirementResult(f, obsMap, riskMap, result, scanTime)
		results = append(results, reqResult)
	}

	tags := map[string]interface{}{
		"nist": []string{nistTag},
	}

	return hdf.EvaluatedRequirement{
		ID:           nistTag,
		Title:        hdfutil.Ptr(title),
		Impact:       impact,
		Tags:         tags,
		Descriptions: descriptions,
		Results:      results,
		ControlType:  shared.DeriveControlTypeFromTags([]string{nistTag}),
	}
}

// findingToRequirementResult converts a single Finding to a RequirementResult.
func findingToRequirementResult(
	f *Finding,
	obsMap map[string]*Observation,
	riskMap map[string]*Risk,
	result *Result,
	scanTime time.Time,
) hdf.RequirementResult {
	// Map status
	status := mapFindingStatus(f)

	// Build code description from observation methods and subjects
	codeDesc := buildCodeDesc(f, obsMap)

	// Build message from risk descriptions
	message := buildRiskMessage(f, riskMap)

	// Parse start time from result; fall back to the single conversion-time
	// value when the source omits it (startTime is required and must be valid).
	startTime := parseResultStartTime(result)
	if startTime.IsZero() {
		startTime = scanTime
	}

	reqResult := hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc,
		StartTime: startTime,
	}

	if message != "" {
		reqResult.Message = hdfutil.Ptr(message)
	}

	return reqResult
}

// extractControlIDFromFinding extracts the base control ID from a finding's
// target. For objective-id targets like "ac-1.a.1_obj.1", extracts "ac-1".
// For statement-id targets like "au-1_smt.a", extracts "au-1".
func extractControlIDFromFinding(f *Finding) string {
	targetID := f.Target.TargetID
	if targetID == "" {
		return "unknown"
	}

	// For objective-id and statement-id, extract the base control ID
	controlID := ExtractControlIDFromObjectiveID(targetID)

	// Handle statement-id format: "au-1_smt.a" → "au-1"
	if idx := strings.Index(controlID, "_"); idx > 0 {
		controlID = controlID[:idx]
	}

	return controlID
}

// mapFindingStatus maps a finding's target status to an HDF ResultStatus.
func mapFindingStatus(f *Finding) hdf.ResultStatus {
	if status, ok := OscalStatusToHDF(f.Target.Status.State); ok {
		switch status {
		case "passed":
			return hdf.Passed
		case "failed":
			return hdf.Failed
		}
	}
	return hdf.NotReviewed
}

// buildCodeDesc builds a code description from observation methods and subjects.
func buildCodeDesc(f *Finding, obsMap map[string]*Observation) string {
	var parts []string

	for _, ref := range f.RelatedObservations {
		obs, ok := obsMap[ref.ObservationUUID]
		if !ok {
			continue
		}

		// Include methods
		if len(obs.Methods) > 0 {
			parts = append(parts, "Methods: "+strings.Join(obs.Methods, ", "))
		}

		// Include subject summaries
		for _, subj := range obs.Subjects {
			subjDesc := subj.Type
			if subj.Title != "" {
				subjDesc = subj.Title + " (" + subj.Type + ")"
			}
			parts = append(parts, "Subject: "+subjDesc)
		}
	}

	if len(parts) == 0 {
		return f.Title
	}

	return strings.Join(parts, "; ")
}

// buildRiskMessage builds a message string from related risk descriptions.
func buildRiskMessage(f *Finding, riskMap map[string]*Risk) string {
	var messages []string

	for _, ref := range f.RelatedRisks {
		risk, ok := riskMap[ref.RiskUUID]
		if !ok {
			continue
		}

		msg := risk.Title
		if risk.Description != "" {
			msg += ": " + risk.Description
		}
		messages = append(messages, msg)
	}

	return strings.Join(messages, "\n")
}

// sarFindingsImpact determines the impact value from related risks across
// all findings for a control. Uses ExtractRiskSeverity on each risk's
// characterizations and returns the highest impact found.
func sarFindingsImpact(findings []*Finding, riskMap map[string]*Risk) float64 {
	highestImpact := -1.0

	for _, f := range findings {
		for _, ref := range f.RelatedRisks {
			risk, ok := riskMap[ref.RiskUUID]
			if !ok {
				continue
			}
			impact := ExtractRiskSeverity(risk.Characterizations, -1.0)
			if impact > highestImpact {
				highestImpact = impact
			}
		}
	}

	if highestImpact < 0 {
		return 0.5 // default medium impact
	}
	return highestImpact
}

// sarBuildDescriptions creates HDF Description entries from findings and
// their related observations.
func sarBuildDescriptions(findings []*Finding, obsMap map[string]*Observation) []hdf.Description {
	descriptions := make([]hdf.Description, 0, 2)

	// Default description from finding descriptions
	var findingDescs []string
	for _, f := range findings {
		if f.Description != "" {
			findingDescs = append(findingDescs, f.Description)
		}
	}
	defaultDesc := strings.Join(findingDescs, "\n")
	if defaultDesc == "" {
		defaultDesc = ""
	}
	descriptions = append(descriptions, hdf.Description{
		Label: "default",
		Data:  defaultDesc,
	})

	// Rationale from observation descriptions
	var obsDescs []string
	seen := make(map[string]bool)
	for _, f := range findings {
		for _, ref := range f.RelatedObservations {
			if seen[ref.ObservationUUID] {
				continue
			}
			seen[ref.ObservationUUID] = true
			obs, ok := obsMap[ref.ObservationUUID]
			if !ok {
				continue
			}
			if obs.Description != "" {
				obsDescs = append(obsDescs, obs.Description)
			}
		}
	}
	if len(obsDescs) > 0 {
		descriptions = append(descriptions, hdf.Description{
			Label: "rationale",
			Data:  strings.Join(obsDescs, "\n"),
		})
	}

	return descriptions
}

// buildObservationMap creates a UUID → Observation lookup.
func buildObservationMap(observations []Observation) map[string]*Observation {
	m := make(map[string]*Observation, len(observations))
	for i := range observations {
		m[observations[i].UUID] = &observations[i]
	}
	return m
}

// parseResultStartTime parses the start time from an OSCAL Result.
func parseResultStartTime(result *Result) time.Time {
	if result.Start != "" {
		if t, err := time.Parse(time.RFC3339, result.Start); err == nil {
			return t
		}
	}
	return time.Time{}
}

// sarBaselineName derives a baseline name from the result title or SAR metadata.
func sarBaselineName(result *Result, sar *AssessmentResults) string {
	title := result.Title
	if title == "" {
		title = sar.Metadata.Title
	}
	return ToKebabCase(title, "oscal-assessment-results")
}
