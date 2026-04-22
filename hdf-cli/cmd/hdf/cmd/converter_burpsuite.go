package cmd

import burpsuite "github.com/mitre/hdf-libs/hdf-converters/converters/burpsuite-to-hdf/go"

func init() {
	registerHDFConverter("burpsuite", "BurpSuite to HDF", "burpsuite", burpsuite.ConvertBurpsuiteToHDF)
}
