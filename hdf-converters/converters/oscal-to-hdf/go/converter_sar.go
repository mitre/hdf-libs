package oscal

import (
	"log"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
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
		if t := hdfutil.ParseTimestamp(meta.LastModified); !t.IsZero() {
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

	// Build descriptions from findings, observations, and related risks
	descriptions := sarBuildDescriptions(findings, obsMap, riskMap)

	// Build external references from observation relevant-evidence
	refs := sarBuildRefs(findings, obsMap)

	// Build results from each finding
	results := make([]hdf.RequirementResult, 0, len(findings))
	for _, f := range findings {
		reqResult := findingToRequirementResult(f, obsMap, riskMap, result, scanTime)
		results = append(results, reqResult)
	}

	// tags.nist carries the finding's NIST control; tags.cci is derived from it
	// via the standard NIST→CCI mapping (omitted when the control maps to none),
	// matching how sibling converters emit both.
	nistTags := []string{nistTag}
	tags := shared.BuildNISTCCITags(nistTags, cci.NISTToCCI(nistTags))

	return hdf.EvaluatedRequirement{
		ID:           nistTag,
		Title:        hdfutil.Ptr(title),
		Impact:       impact,
		Tags:         tags,
		Descriptions: descriptions,
		Refs:         refs,
		Results:      results,
		ControlType:  shared.DeriveControlTypeFromTags(nistTags),
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

	// startTime: prefer the earliest observation `collected` time correlated to
	// this finding via related-observations; fall back to the result's
	// assessment-period start, then to the single conversion-time value.
	// startTime is required and must be valid.
	startTime := findingStartTime(f, obsMap)
	if startTime.IsZero() {
		startTime = parseResultStartTime(result)
	}
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

// sarBuildDescriptions creates HDF Description entries from findings, their
// related observations, and related risks. The "default" and "rationale"
// labels come from finding/observation prose; "statement", "remediation", and
// "evidence" carry the risk statement, recommended remediations, and
// relevant-evidence prose that the source provides.
func sarBuildDescriptions(findings []*Finding, obsMap map[string]*Observation, riskMap map[string]*Risk) []hdf.Description {
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

	// Risk statement text from related risks.
	if statement := collectRiskStatements(findings, riskMap); statement != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "statement",
			Data:  statement,
		})
	}

	// Recommended remediation text from related risks.
	if remediation := collectRemediations(findings, riskMap); remediation != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "remediation",
			Data:  remediation,
		})
	}

	// Relevant-evidence prose from related observations.
	if evidence := collectEvidenceDescriptions(findings, obsMap); evidence != "" {
		descriptions = append(descriptions, hdf.Description{
			Label: "evidence",
			Data:  evidence,
		})
	}

	return descriptions
}

// collectRiskStatements gathers the risk `statement` prose from every related
// risk (deduplicated by risk UUID), joined by newlines. Returns "" when no
// related risk carries a statement.
func collectRiskStatements(findings []*Finding, riskMap map[string]*Risk) string {
	var statements []string
	seen := make(map[string]bool)
	for _, f := range findings {
		for _, ref := range f.RelatedRisks {
			if seen[ref.RiskUUID] {
				continue
			}
			seen[ref.RiskUUID] = true
			risk, ok := riskMap[ref.RiskUUID]
			if !ok {
				continue
			}
			if risk.Statement != "" {
				statements = append(statements, risk.Statement)
			}
		}
	}
	return strings.Join(statements, "\n")
}

// collectRemediations gathers the recommended-remediation prose from every
// related risk (deduplicated by risk UUID). Each remediation renders as
// "title: description" (or whichever of the two the source provides). Entries
// are separated by blank lines. Returns "" when no remediation carries text.
func collectRemediations(findings []*Finding, riskMap map[string]*Risk) string {
	var remediations []string
	seen := make(map[string]bool)
	for _, f := range findings {
		for _, ref := range f.RelatedRisks {
			if seen[ref.RiskUUID] {
				continue
			}
			seen[ref.RiskUUID] = true
			risk, ok := riskMap[ref.RiskUUID]
			if !ok {
				continue
			}
			for i := range risk.Remediations {
				if text := remediationText(&risk.Remediations[i]); text != "" {
					remediations = append(remediations, text)
				}
			}
		}
	}
	return strings.Join(remediations, "\n\n")
}

// remediationText renders a single remediation as "title: description",
// degrading to whichever field is present. Returns "" when both are empty.
func remediationText(rem *Remediation) string {
	switch {
	case rem.Title != "" && rem.Description != "":
		return rem.Title + ": " + rem.Description
	case rem.Title != "":
		return rem.Title
	default:
		return rem.Description
	}
}

// collectEvidenceDescriptions gathers relevant-evidence prose from every
// related observation (observations deduplicated by UUID, evidence prose
// deduplicated by text), joined by newlines. Returns "" when none is present.
func collectEvidenceDescriptions(findings []*Finding, obsMap map[string]*Observation) string {
	var descs []string
	seenObs := make(map[string]bool)
	seenText := make(map[string]bool)
	for _, f := range findings {
		for _, ref := range f.RelatedObservations {
			if seenObs[ref.ObservationUUID] {
				continue
			}
			seenObs[ref.ObservationUUID] = true
			obs, ok := obsMap[ref.ObservationUUID]
			if !ok {
				continue
			}
			for _, ev := range obs.RelevantEvidence {
				if ev.Description == "" || seenText[ev.Description] {
					continue
				}
				seenText[ev.Description] = true
				descs = append(descs, ev.Description)
			}
		}
	}
	return strings.Join(descs, "\n")
}

// sarBuildRefs builds external HDF references from the relevant-evidence hrefs
// of related observations. Only resolvable URLs (those carrying a scheme, e.g.
// "https://…") become references; intra-document fragment hrefs ("#uuid") are
// skipped. URLs are deduplicated. Returns nil when the source carries none.
func sarBuildRefs(findings []*Finding, obsMap map[string]*Observation) []hdf.Reference {
	var refs []hdf.Reference
	seenObs := make(map[string]bool)
	seenURL := make(map[string]bool)
	for _, f := range findings {
		for _, ref := range f.RelatedObservations {
			if seenObs[ref.ObservationUUID] {
				continue
			}
			seenObs[ref.ObservationUUID] = true
			obs, ok := obsMap[ref.ObservationUUID]
			if !ok {
				continue
			}
			for _, ev := range obs.RelevantEvidence {
				if !isResolvableURL(ev.Href) || seenURL[ev.Href] {
					continue
				}
				seenURL[ev.Href] = true
				url := ev.Href
				refs = append(refs, hdf.Reference{URL: &url})
			}
		}
	}
	return refs
}

// isResolvableURL reports whether href is an absolute, resolvable URL (has a
// "scheme://" prefix) rather than an intra-document fragment or empty value.
func isResolvableURL(href string) bool {
	return strings.Contains(href, "://")
}

// buildObservationMap creates a UUID → Observation lookup.
func buildObservationMap(observations []Observation) map[string]*Observation {
	m := make(map[string]*Observation, len(observations))
	for i := range observations {
		m[observations[i].UUID] = &observations[i]
	}
	return m
}

// findingStartTime lifts the earliest observation `collected` time across the
// finding's related observations (correlated by observation UUID). Empty or
// unparseable `collected` values are skipped via ParseTimestamp's zero-time
// sentinel — the TS side mirrors this skip so both languages agree. Returns the
// zero time when no correlated observation carries a usable collected time.
func findingStartTime(f *Finding, obsMap map[string]*Observation) time.Time {
	var earliest time.Time
	for _, ref := range f.RelatedObservations {
		obs, ok := obsMap[ref.ObservationUUID]
		if !ok {
			continue
		}
		t := hdfutil.ParseTimestamp(obs.Collected)
		if t.IsZero() {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest
}

// parseResultStartTime parses the start time from an OSCAL Result.
func parseResultStartTime(result *Result) time.Time {
	if result.Start != "" {
		if t := hdfutil.ParseTimestamp(result.Start); !t.IsZero() {
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
