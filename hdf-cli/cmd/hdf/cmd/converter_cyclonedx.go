package cmd

import cyclonedx "github.com/mitre/hdf-libs/hdf-converters/converters/cyclonedx-to-hdf/go"

func init() {
	registerHDFConverter("cyclonedx", "CycloneDX to HDF", "cyclonedx", cyclonedx.ConvertCycloneDXToHDF)
}
