package cmd

import neuvector "github.com/mitre/hdf-converters/converters/neuvector-to-hdf/go"

func init() {
	registerHDFConverter("neuvector", "NeuVector to HDF", "neuvector", neuvector.ConvertNeuVectorToHDF)
}
