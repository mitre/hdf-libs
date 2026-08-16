package cmd

import spdxvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/spdx-vex-to-hdf/go"

func init() {
	registerHDFAmendmentsConverter("spdx-vex", "SPDX VEX to HDF Amendments", "spdx-vex", spdxvex.ConvertSPDXVEXToHDF)
}
