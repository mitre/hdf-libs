package cmd

import scoutsuite "github.com/mitre/hdf-libs/hdf-converters/v3/converters/scoutsuite-to-hdf/go"

func init() {
	registerHDFConverter("scoutsuite", "ScoutSuite to HDF", "scoutsuite", scoutsuite.ConvertScoutsuiteToHDF)
}
