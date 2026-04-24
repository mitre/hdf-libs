package cmd

import conveyor "github.com/mitre/hdf-libs/hdf-converters/v3/converters/conveyor-to-hdf/go"

func init() {
	registerHDFConverter("conveyor", "Conveyor to HDF", "conveyor", conveyor.ConvertConveyorToHDF)
}
