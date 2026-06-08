package cmd

import cyclonedxvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/cyclonedx-vex-to-hdf/go"

func init() {
	registerHDFAmendmentsConverter("cyclonedx-vex", "CycloneDX VEX to HDF Amendments", "cyclonedx-vex", cyclonedxvex.ConvertCycloneDXVEXToHDF)
}
