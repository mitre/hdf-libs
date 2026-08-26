package convert

import (
	hdftoasff "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-asff/go"
)

type hdfToASFFConverter struct{}

func (c *hdfToASFFConverter) Name() string {
	return "HDF Results to ASFF Findings"
}

func (c *hdfToASFFConverter) Convert(input []byte) ([]byte, error) {
	return hdftoasff.ConvertHDFToASFF(input, version)
}

func init() {
	RegisterConverter("hdf", "asff", &hdfToASFFConverter{})
}
