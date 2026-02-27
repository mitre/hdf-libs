package cmd

import xccdf "github.com/mitre/hdf-converters/converters/xccdf-results-to-hdf/go"

func init() {
	registerHDFConverterMulti(
		[]string{"xccdf", "arf"},
		"XCCDF/ARF to HDF", "xccdf",
		xccdf.ConvertXccdfResultsToHDF,
	)
}
