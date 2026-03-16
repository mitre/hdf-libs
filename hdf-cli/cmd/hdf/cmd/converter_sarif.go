package cmd

import sarif "github.com/mitre/hdf-converters/converters/sarif-to-hdf/go"

func init() {
	registerHDFConverter("sarif", "SARIF to HDF", "sarif", sarif.ConvertSarifToHDF)
}
