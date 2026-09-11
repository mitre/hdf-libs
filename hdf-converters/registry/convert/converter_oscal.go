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
		WithExpectedRequirementCount(oscal.ExpectedCatalogRequirementCount),
	)

	// oscal-component-definition / oscal-component — Convert component definition
	// to baseline. The second name is what auto-detect derives from the
	// oscal-component-to-hdf fingerprint.
	registerHDFBaselineConverterMulti(
		[]string{"oscal-component-definition", "oscal-component"},
		"OSCAL Component Definition to HDF Baseline", "oscal-component-definition",
		oscal.ConvertComponentDefinitionToHDF,
		WithExpectedRequirementCount(oscal.ExpectedComponentDefinitionRequirementCount),
	)

	// oscal-ssp — Convert system security plan to HDF system
	registerRawConverter(
		"oscal-ssp",
		"OSCAL System Security Plan to HDF System", "oscal-ssp",
		oscalSSPRawConvert,
	)

	// oscal-profile — Resolve profile against catalog, produce baseline
	RegisterConverter("oscal-profile", "hdf", &oscalProfileConverter{})

	// oscal-assessment-plan / oscal-sap — Convert assessment plan to HDF plan.
	// The second name is what auto-detect derives from the oscal-sap-to-hdf
	// fingerprint.
	registerHDFPlanConverterMulti(
		[]string{"oscal-assessment-plan", "oscal-sap"},
		"OSCAL Assessment Plan to HDF Plan", "oscal-assessment-plan",
		oscal.ConvertAssessmentPlanToHDF,
		WithExpectedRequirementCount(oscal.ExpectedAssessmentPlanRequirementCount),
	)

	// oscal-poam — Convert POA&M to HDF amendments
	registerHDFAmendmentsConverter(
		"oscal-poam",
		"OSCAL POA&M to HDF Amendments", "oscal-poam",
		oscal.ConvertPOAMToHDF,
		WithExpectedRequirementCount(oscal.ExpectedPOAMRequirementCount),
	)

	// oscal-assessment-results / oscal-sar — Convert SAR to HDF results
	registerHDFConverterMulti(
		[]string{"oscal-assessment-results", "oscal-sar"},
		"OSCAL Assessment Results to HDF", "oscal-assessment-results",
		oscal.ConvertAssessmentResultsToHDF,
		WithExpectedRequirementCount(oscal.ExpectedAssessmentResultsRequirementCount),
	)

	// oscal — Auto-detect OSCAL document type and delegate, relation included.
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

// oscalDelegate resolves the typed converter for the detected document type.
// Convert and ExpectedRequirementCount share it so both route identically.
func oscalDelegate(input []byte) (Converter, string, error) {
	docType, err := oscal.DetectDocumentType(input)
	if err != nil {
		return nil, "", fmt.Errorf("oscal auto-detect failed: %w", err)
	}

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
		return nil, "", fmt.Errorf("oscal auto-detect: unsupported document type %q", docType)
	}

	delegate, err := GetConverter(converterName, "hdf")
	if err != nil {
		return nil, "", fmt.Errorf("oscal auto-detect: no converter for %s: %w", docType, err)
	}
	return delegate, docType, nil
}

func (c *oscalAutoDetectConverter) Convert(input []byte) ([]byte, error) {
	delegate, _, err := oscalDelegate(input)
	if err != nil {
		return nil, err
	}
	return delegate.Convert(input)
}

// ExpectedRequirementCount routes to the delegate's relation. An SSP yields an
// hdf-system document with no primary items, so the converter states no
// relation for it rather than a count.
func (c *oscalAutoDetectConverter) ExpectedRequirementCount(input []byte) (int, string, error) {
	delegate, docType, err := oscalDelegate(input)
	if err != nil {
		return 0, "", err
	}
	if docType == "system-security-plan" {
		return 0, "", ErrNoExpectation
	}
	ex, ok := delegate.(RequirementCountExpecter)
	if !ok {
		return 0, "", ErrNoExpectation
	}
	return ex.ExpectedRequirementCount(input)
}

// oscalProfileConverter handles OSCAL profile → HDF baseline conversion,
// requiring a separate catalog input via the catalog path (SetOSCALCatalogPath).
type oscalProfileConverter struct{}

func (c *oscalProfileConverter) Name() string {
	return "OSCAL Profile to HDF Baseline"
}

// readOSCALCatalog loads the catalog the profile is resolved against. Convert
// and ExpectedRequirementCount share it so both fail identically without one.
func readOSCALCatalog() ([]byte, error) {
	if oscalCatalogPath == "" {
		return nil, fmt.Errorf("--catalog flag is required for oscal-profile conversion.\n" +
			"Usage: hdf convert oscal-profile to hdf profile.json --catalog catalog.json [output.json]\n" +
			"The catalog must be a full OSCAL catalog JSON file (e.g., NIST SP 800-53)")
	}

	catalogData, err := os.ReadFile(oscalCatalogPath) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog file %q: %w", oscalCatalogPath, err)
	}
	return catalogData, nil
}

// ExpectedRequirementCount implements RequirementCountExpecter by resolving
// the profile against the same catalog Convert uses.
func (c *oscalProfileConverter) ExpectedRequirementCount(input []byte) (int, string, error) {
	catalogData, err := readOSCALCatalog()
	if err != nil {
		return 0, "", err
	}
	return oscal.ExpectedProfileRequirementCount(input, catalogData)
}

func (c *oscalProfileConverter) Convert(input []byte) ([]byte, error) {
	catalogData, err := readOSCALCatalog()
	if err != nil {
		return nil, err
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
