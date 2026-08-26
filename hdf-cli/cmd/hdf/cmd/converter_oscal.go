package cmd

import (
	"github.com/spf13/cobra"
)

// oscalCatalogFlag holds the --catalog flag value for the oscal-profile
// converter. The convert command syncs it into the lifted registry via
// convreg.SetOSCALCatalogPath before running the converter (see convert.go).
var oscalCatalogFlag string

// AddOSCALFlags adds OSCAL-specific flags to the convert command.
func AddOSCALFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&oscalCatalogFlag, "catalog", "",
		"Path to OSCAL catalog JSON file (required for oscal-profile conversion)")
}
