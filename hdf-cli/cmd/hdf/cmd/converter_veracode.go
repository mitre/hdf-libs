package cmd

import veracode "github.com/mitre/hdf-libs/hdf-converters/converters/veracode-to-hdf/go"

func init() {
	registerHDFConverter("veracode", "Veracode to HDF", "veracode", veracode.ConvertVeracodeToHDF)
}
