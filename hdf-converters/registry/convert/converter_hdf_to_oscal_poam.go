package convert

import (
	hdftooscalpoam "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-oscal-poam/go"
)

type hdfToOSCALPOAMConverter struct{}

func (c *hdfToOSCALPOAMConverter) Name() string {
	return "HDF Amendments to OSCAL POA&M"
}

func (c *hdfToOSCALPOAMConverter) Convert(input []byte) ([]byte, error) {
	return hdftooscalpoam.ConvertHDFToOSCALPOAM(input, version)
}

func init() {
	RegisterConverter("hdf-amendments", "oscal-poam", &hdfToOSCALPOAMConverter{})
}
