package convert

import (
	hdftockl "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ckl/go"
)

//nolint:dupl // thin reverse-converter wrapper mirrors converter_hdf_to_csv.go by design
type hdfToCKLConverter struct{}

func (c *hdfToCKLConverter) Name() string {
	return "HDF to CKL"
}

func (c *hdfToCKLConverter) Convert(input []byte) ([]byte, error) {
	return hdftockl.ConvertHDFToCKL(input)
}

func init() {
	RegisterConverter("hdf", "ckl", &hdfToCKLConverter{})
}
