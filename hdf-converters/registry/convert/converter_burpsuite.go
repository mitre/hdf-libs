package convert

import burpsuite "github.com/mitre/hdf-libs/hdf-converters/v3/converters/burpsuite-to-hdf/go"

func init() {
	registerHDFConverter("burpsuite", "BurpSuite to HDF", "burpsuite", burpsuite.ConvertBurpsuiteToHDF)
}
