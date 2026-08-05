package convert

import (
	hdftosplunk "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-splunk/go"
)

type hdfToSplunkConverter struct{}

func (c *hdfToSplunkConverter) Name() string {
	return "HDF Results to Splunk (CIM/HEC)"
}

func (c *hdfToSplunkConverter) Convert(input []byte) ([]byte, error) {
	return hdftosplunk.ConvertHDFToSplunk(input, version)
}

func init() {
	RegisterConverter("hdf", "splunk", &hdfToSplunkConverter{})
}
