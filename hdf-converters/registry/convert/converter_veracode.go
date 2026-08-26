package convert

import veracode "github.com/mitre/hdf-libs/hdf-converters/v3/converters/veracode-to-hdf/go"

func init() {
	registerHDFConverter("veracode", "Veracode to HDF", "veracode", veracode.ConvertVeracodeToHDF)
}
