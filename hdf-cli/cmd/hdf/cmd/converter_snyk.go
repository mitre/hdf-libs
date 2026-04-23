package cmd

import snyk "github.com/mitre/hdf-libs/hdf-converters/converters/snyk-to-hdf/go"

func init() {
	registerHDFConverter("snyk", "Snyk to HDF", "snyk", snyk.ConvertSnykToHDF)
}
