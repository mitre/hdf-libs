package cmd

import csafvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/csaf-vex-to-hdf/go"

func init() {
	registerHDFAmendmentsConverter("csaf-vex", "CSAF VEX to HDF Amendments", "csaf-vex", csafvex.ConvertCSAFVEXToHDF)
}
