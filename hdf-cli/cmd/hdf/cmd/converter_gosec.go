package cmd

import gosec "github.com/mitre/hdf-converters/converters/gosec-to-hdf/go"

func init() {
	registerHDFConverter("gosec", "gosec to HDF", "gosec", gosec.ConvertGosecToHDF)
}
