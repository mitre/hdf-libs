package cmd

import (
	hdftocklb "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-cklb/go"
)

//nolint:dupl // mirrors the other thin reverse-converter wrappers by design
type hdfToCKLBConverter struct{}

func (c *hdfToCKLBConverter) Name() string {
	return "HDF to CKLB"
}

func (c *hdfToCKLBConverter) Convert(input []byte) ([]byte, error) {
	return hdftocklb.ConvertHDFToCKLB(input)
}

func init() {
	RegisterConverter("hdf", "cklb", &hdfToCKLBConverter{})
}
