package convert

import trivy "github.com/mitre/hdf-libs/hdf-converters/v3/converters/trivy-to-hdf/go"

func init() {
	registerHDFConverter("trivy", "Trivy to HDF", "trivy", trivy.ConvertTrivyToHDF)
}
