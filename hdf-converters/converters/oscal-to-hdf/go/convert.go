package oscal

import "fmt"

// ConvertOSCALToHDF is the domain-level auto-detect entry point: it detects the
// OSCAL document type and dispatches to the matching per-type converter,
// returning the appropriate HDF document (baseline / system / plan / results /
// amendments) as interface{}. This is the single seam the CLI auto-detect
// wrapper and the snapshot harness share.
//
// Profile resolution requires a separate catalog input, so it cannot be handled
// from a single document; callers that need it must invoke ConvertProfileToHDF
// directly with both inputs.
func ConvertOSCALToHDF(input []byte, converterVersion string) (interface{}, error) {
	docType, err := DetectDocumentType(input)
	if err != nil {
		return nil, err
	}

	switch docType {
	case "catalog":
		return ConvertCatalogToHDF(input, converterVersion)
	case "component-definition":
		return ConvertComponentDefinitionToHDF(input, converterVersion)
	case "system-security-plan":
		return ConvertSSPToHDF(input, converterVersion)
	case "assessment-plan":
		return ConvertAssessmentPlanToHDF(input, converterVersion)
	case "assessment-results":
		return ConvertAssessmentResultsToHDF(input, converterVersion)
	case "plan-of-action-and-milestones":
		return ConvertPOAMToHDF(input, converterVersion)
	case "profile":
		return nil, fmt.Errorf("oscal profile requires a separate catalog input; call ConvertProfileToHDF with both documents")
	default:
		return nil, fmt.Errorf("unsupported OSCAL document type %q", docType)
	}
}
