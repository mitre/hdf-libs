package cmd

import nessus "github.com/mitre/hdf-converters/converters/nessus-to-hdf/go"

func init() {
	registerHDFConverter("nessus", "Nessus to HDF", "nessus", nessus.ConvertNessusToHDF)
}
