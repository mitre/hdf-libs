package convert

import checkov "github.com/mitre/hdf-libs/hdf-converters/v3/converters/checkov-to-hdf/go"

func init() {
	registerHDFConverter("checkov", "Checkov to HDF", "checkov", checkov.ConvertCheckovToHDF)
}
