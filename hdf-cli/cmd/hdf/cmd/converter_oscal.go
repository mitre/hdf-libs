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

	// oscal-profile — Resolve profile against catalog, produce baseline
	RegisterConverter("oscal-profile", "hdf", &oscalProfileConverter{})
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
