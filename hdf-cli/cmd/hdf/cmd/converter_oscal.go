package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	oscal "github.com/mitre/hdf-converters/converters/oscal-to-hdf/go"
	"github.com/spf13/cobra"
)

// oscalCatalogFlag holds the --catalog flag value for the oscal-profile converter.
var oscalCatalogFlag string

// AddOSCALFlags adds OSCAL-specific flags to the convert command.
func AddOSCALFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&oscalCatalogFlag, "catalog", "",
		"Path to OSCAL catalog JSON file (required for oscal-profile conversion)")
}

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

// oscalProfileConverter handles OSCAL profile → HDF baseline conversion,
// requiring a separate catalog input via the --catalog flag.
type oscalProfileConverter struct{}

func (c *oscalProfileConverter) Name() string {
	return "OSCAL Profile to HDF Baseline"
}

func (c *oscalProfileConverter) Convert(input []byte) ([]byte, error) {
	if oscalCatalogFlag == "" {
		return nil, fmt.Errorf("--catalog flag is required for oscal-profile conversion.\n" +
			"Usage: hdf convert oscal-profile to hdf profile.json --catalog catalog.json [output.json]\n" +
			"The catalog must be a full OSCAL catalog JSON file (e.g., NIST SP 800-53)")
	}

	catalogData, err := os.ReadFile(oscalCatalogFlag) // #nosec G304 -- CLI reads user-provided file path
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog file %q: %w", oscalCatalogFlag, err)
	}

	baseline, err := oscal.ConvertProfileToHDF(input, catalogData, version)
	if err != nil {
		return nil, fmt.Errorf("oscal-profile conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}
