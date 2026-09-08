package oscal

import (
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertAssessmentPlanToHDF converts an OSCAL Assessment Plan (SAP) document
// to an HDFPlan. Each control-selection maps to an Assessment entry, and the
// import-ssp reference becomes the systemRef.
func ConvertAssessmentPlanToHDF(input []byte, converterVersion string) (*hdf.HDFPlan, error) {
	doc, err := ParseOscalDocument(input, "assessment-plan", "oscal-assessment-plan")
	if err != nil {
		return nil, err
	}

	return assessmentPlanToHDFPlan(doc.AssessmentPlan, input, converterVersion)
}

// ExpectedAssessmentPlanRequirementCount states how many assessments a plan
// must convert to: one per control-selection, else one per
// control-objective-selection, else one synthetic assessment — and none when
// the plan carries no reviewed-controls at all. Computed from the input alone,
// through the same selection the conversion uses.
func ExpectedAssessmentPlanRequirementCount(input []byte) (int, string, error) {
	const unit = "OSCAL reviewed-control selections"
	doc, err := ParseOscalDocument(input, "assessment-plan", "oscal-assessment-plan")
	if err != nil {
		return 0, unit, err
	}
	return len(selectAssessmentSources(doc.AssessmentPlan)), unit, nil
}

// assessmentPlanToHDFPlan converts a parsed AssessmentPlan to HDFPlan.
func assessmentPlanToHDFPlan(ap *AssessmentPlan, rawInput []byte, converterVersion string) (*hdf.HDFPlan, error) {
	integrity := shared.InputIntegrity(rawInput)
	meta := ExtractMetadata(ap.Metadata)

	// Build assessments from reviewed-controls
	assessments := buildAssessments(ap)

	// Extract systemRef from import-ssp
	var systemRef *string
	if ap.ImportSSP != nil && ap.ImportSSP.Href != "" {
		systemRef = hdfutil.Ptr(ap.ImportSSP.Href)
	}

	// Determine plan type from assessment-assets/tasks
	planType := determinePlanType(ap)

	// Build description from metadata remarks and terms-and-conditions
	description := buildPlanDescription(ap)

	genName := "oscal-sap-to-hdf"
	plan := &hdf.HDFPlan{
		Name:        ToKebabCase(ap.Metadata.Title, "oscal-assessment-plan"),
		Assessments: assessments,
		Integrity:   integrity,
		SystemRef:   systemRef,
		Version:     hdfutil.Ptr(meta.Version),
		Type:        planType,
		Description: description,
		Generator: &hdf.Generator{
			Name:    genName,
			Version: converterVersion,
		},
	}

	return plan, nil
}

// assessmentSource is what one HDF assessment is built from: a
// control-selection, a control-objective-selection, or neither (synthetic).
type assessmentSource struct {
	selection *ControlSelection
	objective *ControlObjective
}

// selectAssessmentSources is the single definition of the plan's
// input-to-assessment relation: control-selections when present, else
// control-objective-selections, else one synthetic source; a plan with no
// reviewed-controls section yields none. The conversion builds assessments
// from it and ExpectedAssessmentPlanRequirementCount counts it.
func selectAssessmentSources(ap *AssessmentPlan) []assessmentSource {
	if ap.ReviewedControls == nil {
		return nil
	}
	var sources []assessmentSource
	for i := range ap.ReviewedControls.ControlSelections {
		sources = append(sources, assessmentSource{selection: &ap.ReviewedControls.ControlSelections[i]})
	}
	if len(sources) == 0 {
		for i := range ap.ReviewedControls.ControlObjectives {
			sources = append(sources, assessmentSource{objective: &ap.ReviewedControls.ControlObjectives[i]})
		}
	}
	if len(sources) == 0 {
		sources = append(sources, assessmentSource{})
	}
	return sources
}

// buildAssessments creates HDF Assessment entries from the reviewed-controls
// section of the assessment plan.
func buildAssessments(ap *AssessmentPlan) []hdf.Assessment {
	sources := selectAssessmentSources(ap)
	assessments := make([]hdf.Assessment, 0, len(sources))
	for _, src := range sources {
		switch {
		case src.selection != nil:
			cs := src.selection
			assessment := hdf.Assessment{
				// Derive baselineRef from the import-ssp reference or control selection description
				BaselineRef: deriveBaselineRef(ap, cs),
				// Extract runner info from assessment-assets
				Runner: extractRunnerConfig(ap),
				// Build target selector from assessment-subjects
				TargetSelector: buildTargetSelector(ap),
			}
			if cs.Description != "" {
				assessment.Description = hdfutil.Ptr(cs.Description)
			}
			assessments = append(assessments, assessment)
		case src.objective != nil:
			co := src.objective
			assessment := hdf.Assessment{
				BaselineRef: deriveBaselineRefFromObjectives(ap, co),
				Runner:      extractRunnerConfig(ap),
			}
			if co.Description != "" {
				assessment.Description = hdfutil.Ptr(co.Description)
			}
			assessments = append(assessments, assessment)
		default:
			// Ensure at least one assessment exists
			assessments = append(assessments, hdf.Assessment{BaselineRef: "oscal-assessment-plan"})
		}
	}

	return assessments
}

// deriveBaselineRef extracts a baseline reference from the assessment plan context.
// It looks at the import-ssp href and control selection metadata.
func deriveBaselineRef(ap *AssessmentPlan, cs *ControlSelection) string {
	// If include-all is set, reference the full baseline from the SSP
	if cs.IncludeAll != nil {
		if ap.ImportSSP != nil && ap.ImportSSP.Href != "" {
			return ap.ImportSSP.Href
		}
		return "all-controls"
	}

	// If specific controls are included, build a reference from the first control ID
	if len(cs.IncludeControls) > 0 {
		ids := make([]string, 0, len(cs.IncludeControls))
		for _, sc := range cs.IncludeControls {
			ids = append(ids, ControlIDToNistTag(sc.ControlID))
		}
		return strings.Join(ids, ",")
	}

	if ap.ImportSSP != nil && ap.ImportSSP.Href != "" {
		return ap.ImportSSP.Href
	}

	return "oscal-assessment-plan"
}

// deriveBaselineRefFromObjectives builds a baseline reference from control objectives.
func deriveBaselineRefFromObjectives(ap *AssessmentPlan, co *ControlObjective) string {
	if co.IncludeAll != nil {
		if ap.ImportSSP != nil && ap.ImportSSP.Href != "" {
			return ap.ImportSSP.Href
		}
		return "all-objectives"
	}

	if len(co.IncludeControls) > 0 {
		ids := make([]string, 0, len(co.IncludeControls))
		for _, sc := range co.IncludeControls {
			ids = append(ids, ExtractControlIDFromObjectiveID(sc.ControlID))
		}
		return strings.Join(ControlIDsToNistTags(ids), ",")
	}

	return "oscal-assessment-plan"
}

// extractRunnerConfig builds RunnerConfig from assessment-assets.
func extractRunnerConfig(ap *AssessmentPlan) *hdf.RunnerConfig {
	if ap.AssessmentAssets == nil {
		return nil
	}

	// Look for the first assessment platform
	if len(ap.AssessmentAssets.AssessmentPlatforms) > 0 {
		platform := ap.AssessmentAssets.AssessmentPlatforms[0]
		config := &hdf.RunnerConfig{}
		if platform.Title != "" {
			config.Name = hdfutil.Ptr(platform.Title)
		}
		return config
	}

	// Fall back to components
	if len(ap.AssessmentAssets.Components) > 0 {
		comp := ap.AssessmentAssets.Components[0]
		config := &hdf.RunnerConfig{}
		config.Name = hdfutil.Ptr(comp.Title)
		if v, ok := ExtractPropValue(comp.Props, "version", ""); ok {
			config.Version = hdfutil.Ptr(v)
		}
		return config
	}

	return nil
}

// buildTargetSelector creates a target selector map from assessment-subjects.
func buildTargetSelector(ap *AssessmentPlan) map[string]string {
	if len(ap.AssessmentSubjects) == 0 {
		return nil
	}

	selector := make(map[string]string)
	for _, subject := range ap.AssessmentSubjects {
		if subject.Type != "" {
			key := "subject-type"
			if _, exists := selector[key]; exists {
				// Append to existing value
				selector[key] += "," + subject.Type
			} else {
				selector[key] = subject.Type
			}
		}
		if subject.IncludeAll != nil {
			selector["include-"+subject.Type] = "all"
		}
	}

	if len(selector) == 0 {
		return nil
	}
	return selector
}

// determinePlanType determines the HDF plan type from assessment plan metadata.
func determinePlanType(ap *AssessmentPlan) *hdf.PlanType {
	// Check assessment-type prop in metadata
	if aType, ok := ExtractPropValue(ap.Metadata.Props, "assessment-type", ""); ok {
		switch strings.ToLower(aType) {
		case "automated":
			pt := hdf.PlanTypeAutomated
			return &pt
		case "manual":
			pt := hdf.PlanTypeManual
			return &pt
		}
	}

	// Default to hybrid if tasks exist (indicates a planned multi-step assessment)
	if len(ap.Tasks) > 0 {
		pt := hdf.PlanTypeHybrid
		return &pt
	}

	return nil
}

// buildPlanDescription builds a description from SAP metadata and terms.
func buildPlanDescription(ap *AssessmentPlan) *string {
	var parts []string

	if ap.Metadata.Remarks != "" {
		parts = append(parts, ap.Metadata.Remarks)
	}

	if ap.TermsAndConditions != nil && len(ap.TermsAndConditions.Parts) > 0 {
		terms := FlattenParts(ap.TermsAndConditions.Parts)
		if terms != "" {
			parts = append(parts, "Terms and Conditions: "+terms)
		}
	}

	if len(parts) == 0 {
		return nil
	}
	desc := strings.Join(parts, "\n\n")
	return &desc
}
