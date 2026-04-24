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

	genName := "hdf-converters"
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

// buildAssessments creates HDF Assessment entries from the reviewed-controls
// section of the assessment plan.
func buildAssessments(ap *AssessmentPlan) []hdf.Assessment {
	if ap.ReviewedControls == nil {
		return []hdf.Assessment{}
	}

	var assessments []hdf.Assessment

	for _, cs := range ap.ReviewedControls.ControlSelections {
		assessment := hdf.Assessment{}

		// Derive baselineRef from the import-ssp reference or control selection description
		assessment.BaselineRef = deriveBaselineRef(ap, &cs)

		// Add description from control selection
		if cs.Description != "" {
			assessment.Description = hdfutil.Ptr(cs.Description)
		}

		// Extract runner info from assessment-assets
		assessment.Runner = extractRunnerConfig(ap)

		// Build target selector from assessment-subjects
		assessment.TargetSelector = buildTargetSelector(ap)

		assessments = append(assessments, assessment)
	}

	// If no control selections but there are control-objective-selections, create
	// assessments from those
	if len(assessments) == 0 && len(ap.ReviewedControls.ControlObjectives) > 0 {
		for _, co := range ap.ReviewedControls.ControlObjectives {
			assessment := hdf.Assessment{
				BaselineRef: deriveBaselineRefFromObjectives(ap, &co),
				Runner:      extractRunnerConfig(ap),
			}
			if co.Description != "" {
				assessment.Description = hdfutil.Ptr(co.Description)
			}
			assessments = append(assessments, assessment)
		}
	}

	// Ensure at least one assessment exists
	if len(assessments) == 0 {
		assessments = append(assessments, hdf.Assessment{
			BaselineRef: "oscal-assessment-plan",
		})
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
			pt := hdf.Automated
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
