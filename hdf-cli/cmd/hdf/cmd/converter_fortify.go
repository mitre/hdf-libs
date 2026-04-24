package cmd

import fortify "github.com/mitre/hdf-libs/hdf-converters/v3/converters/fortify-to-hdf/go"

func init() {
	registerHDFConverter("fortify", "Fortify to HDF", "fortify", fortify.ConvertFortifyToHDF)
}
