package convert

import kics "github.com/mitre/hdf-libs/hdf-converters/v3/converters/kics-to-hdf/go"

func init() {
	registerHDFConverter("kics", "KICS to HDF", "kics", kics.ConvertKicsToHDF)
}
