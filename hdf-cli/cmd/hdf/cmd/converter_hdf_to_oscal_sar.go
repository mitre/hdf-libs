package cmd

import (
	hdftooscalsar "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-oscal-sar/go"
)

type hdfToOSCALSARConverter struct{}

func (c *hdfToOSCALSARConverter) Name() string {
	return "HDF Results to OSCAL SAR"
}

func (c *hdfToOSCALSARConverter) Convert(input []byte) ([]byte, error) {
	return hdftooscalsar.ConvertHDFToOSCALSAR(input, version)
}

func init() {
	RegisterConverter("hdf", "oscal-sar", &hdfToOSCALSARConverter{})
}
