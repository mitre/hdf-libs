package convert

import (
	hdftoocsf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ocsf/go"
)

type hdfToOCSFConverter struct{}

func (c *hdfToOCSFConverter) Name() string {
	return "HDF Results to OCSF Findings"
}

func (c *hdfToOCSFConverter) Convert(input []byte) ([]byte, error) {
	return hdftoocsf.ConvertHDFToOCSF(input, version)
}

func init() {
	RegisterConverter("hdf", "ocsf", &hdfToOCSFConverter{})
}
