package cmd

import nessus "github.com/mitre/hdf-libs/hdf-converters/v3/converters/nessus-to-hdf/go"

func init() {
	registerHDFConverter("nessus", "Nessus to HDF", "nessus", nessus.ConvertNessusToHDF)
}
