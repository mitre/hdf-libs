package convert

import cklb "github.com/mitre/hdf-libs/hdf-converters/v3/converters/cklb-to-hdf/go"

func init() {
	registerHDFConverter("cklb", "CKLB to HDF", "cklb", cklb.ConvertCKLBToHDF)
}
