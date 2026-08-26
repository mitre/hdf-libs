package convert

import asff "github.com/mitre/hdf-libs/hdf-converters/v3/converters/asff-to-hdf/go"

func init() {
	registerHDFConverter("asff", "AWS Security Finding Format to HDF", "asff", asff.ConvertAsffToHDF)
}
