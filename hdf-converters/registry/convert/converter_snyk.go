package convert

import snyk "github.com/mitre/hdf-libs/hdf-converters/v3/converters/snyk-to-hdf/go"

func init() {
	registerHDFConverter("snyk", "Snyk to HDF", "snyk", snyk.ConvertSnykToHDF)
}
