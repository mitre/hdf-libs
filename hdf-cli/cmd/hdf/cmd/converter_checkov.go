package cmd

import checkov "github.com/mitre/hdf-libs/hdf-converters/converters/checkov-to-hdf/go"

func init() {
	registerHDFConverter("checkov", "Checkov to HDF", "checkov", checkov.ConvertCheckovToHDF)
}
