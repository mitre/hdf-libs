package cmd

import (
	hdftoxccdf "github.com/mitre/hdf-converters/converters/hdf-to-xccdf/go"
)

type hdfToXCCDFConverter struct{}

func (c *hdfToXCCDFConverter) Name() string {
	return "HDF to XCCDF"
}

func (c *hdfToXCCDFConverter) Convert(input []byte) ([]byte, error) {
	return hdftoxccdf.ConvertHDFToXCCDF(input, version)
}

func init() {
	RegisterConverter("hdf", "xccdf", &hdfToXCCDFConverter{})
}
