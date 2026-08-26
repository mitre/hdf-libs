package convert

import (
	"encoding/json"
	"fmt"
	"os"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
)

func init() {
	// oscal-catalog — Convert catalog to baseline
	registerHDFBaselineConverter(
		"oscal-catalog",
		"OSCAL Catalog to HDF Baseline", "oscal-catalog",
		oscal.ConvertCatalogToHDF,
	)

	// oscal-component-definition — Convert component definition to baseline
	registerHDFBaselineConverter(
		"oscal-component-definition",
		"OSCAL Component Definition to HDF Baseline", "oscal-component-definition",
		oscal.ConvertComponentDefinitionToHDF,
	)

	// oscal-ssp — Convert system security plan to HDF system
	registerRawConverter(
		"oscal-ssp",
		"OSCAL System Security Plan to HDF System", "oscal-ssp",
		oscalSSPRawConvert,
	)

	// oscal-profile — Resolve profile against catalog, produce baseline
	RegisterConverter("oscal-profile", "hdf", &oscalProfileConverter{})

	// oscal-assessment-plan — Convert assessment plan to HDF plan
	registerHDFPlanConverter(
		"oscal-assessment-plan",
		"OSCAL Assessment Plan to HDF Plan", "oscal-assessment-plan",
		oscal.ConvertAssessmentPlanToHDF,
	)

	// oscal-poam — Convert POA&M to HDF amendments
	registerHDFAmendmentsConverter(
		"oscal-poam",
		"OSCAL POA&M to HDF Amendments", "oscal-poam",
		oscal.ConvertPOAMToHDF,
	)

	// oscal-assessment-results / oscal-sar — Convert SAR to HDF results
	registerHDFConverterMulti(
		[]string{"oscal-assessment-results", "oscal-sar"},
		"OSCAL Assessment Results to HDF", "oscal-assessment-results",
		oscal.ConvertAssessmentResultsToHDF,
	)

	// oscal — Auto-detect OSCAL document type and delegate
	RegisterConverter("oscal", "hdf", &oscalAutoDetectConverter{})
}

// oscalSSPRawConvert wraps the SSP converter to produce raw JSON bytes,
// since HDFSystem is neither HDFResults nor HDFBaseline.
func oscalSSPRawConvert(input []byte, converterVersion string) ([]byte, error) {
	system, err := oscal.ConvertSSPToHDF(input, converterVersion)
	if err != nil {
		return nil, err
	}

	output, err := json.MarshalIndent(system, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

// oscalAutoDetectConverter detects the OSCAL document type and delegates
// to the appropriate converter. Profile requires a catalog so it gets
// special handling.
type oscalAutoDetectConverter struct{}

func (c *oscalAutoDetectConverter) Name() string {
	return "OSCAL (auto-detect) to HDF"
}

func (c *oscalAutoDetectConverter) Convert(input []byte) ([]byte, error) {
	docType, err := oscal.DetectDocumentType(input)
	if err != nil {
		return nil, fmt.Errorf("oscal auto-detect failed: %w", err)
	}

	// Map detected type to registered converter name
	converterName := ""
	switch docType {
	case "catalog":
		converterName = "oscal-catalog"
	case "profile":
		converterName = "oscal-profile"
	case "component-definition":
		converterName = "oscal-component-definition"
	case "system-security-plan":
		converterName = "oscal-ssp"
	case "assessment-plan":
		converterName = "oscal-assessment-plan"
	case "assessment-results":
		converterName = "oscal-assessment-results"
	case "plan-of-action-and-milestones":
		converterName = "oscal-poam"
	default:
		return nil, fmt.Errorf("oscal auto-detect: unsupported document type %q", docType)
	}

	delegate, err := GetConverter(converterName, "hdf")
	if err != nil {
		return nil, fmt.Errorf("oscal auto-detect: no converter for %s: %w", docType, err)
	}

	return delegate.Convert(input)
}

// oscalProfileConverter handles OSCAL profile → HDF baseline conversion,
// requiring a separate catalog input via the catalog path (SetOSCALCatalogPath).
type oscalProfileConverter struct{}

func (c *oscalProfileConverter) Name() string {
	return "OSCAL Profile to HDF Baseline"
}

func (c *oscalProfileConverter) Convert(input []byte) ([]byte, error) {
	if oscalCatalogPath == "" {
		return nil, fmt.Errorf("--catalog flag is required for oscal-profile conversion.\n" +
			"Usage: hdf convert oscal-profile to hdf profile.json --catalog catalog.json [output.json]\n" +
			"The catalog must be a full OSCAL catalog JSON file (e.g., NIST SP 800-53)")
	}

	catalogData, err := os.ReadFile(oscalCatalogPath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog file %q: %w", oscalCatalogPath, err)
	}

	baseline, err := oscal.ConvertProfileToHDF(input, catalogData, version)
	if err != nil {
		return nil, fmt.Errorf("oscal-profile conversion failed (catalog: %s): %w", oscalCatalogPath, err)
	}

	output, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}
