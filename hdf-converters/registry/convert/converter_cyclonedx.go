package convert

import cyclonedx "github.com/mitre/hdf-libs/hdf-converters/v3/converters/cyclonedx-to-hdf/go"

func init() {
	registerHDFConverter("cyclonedx", "CycloneDX to HDF", "cyclonedx", cyclonedx.ConvertCycloneDXToHDF)
}
