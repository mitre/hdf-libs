package cmd

import scoutsuite "github.com/mitre/hdf-converters/converters/scoutsuite-to-hdf/go"

func init() {
	registerHDFConverter("scoutsuite", "ScoutSuite to HDF", "scoutsuite", scoutsuite.ConvertScoutsuiteToHDF)
}
