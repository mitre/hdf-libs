package convert

import neuvector "github.com/mitre/hdf-libs/hdf-converters/v3/converters/neuvector-to-hdf/go"

func init() {
	registerHDFConverter("neuvector", "NeuVector to HDF", "neuvector", neuvector.ConvertNeuVectorToHDF)
}
