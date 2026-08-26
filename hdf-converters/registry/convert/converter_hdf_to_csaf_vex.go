package convert

import (
	"fmt"

	hdftocsafvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-csaf-vex/go"
)

type hdfToCSAFVEXConverter struct{}

func (c *hdfToCSAFVEXConverter) Name() string { return "HDF Amendments to CSAF VEX" }

func (c *hdfToCSAFVEXConverter) Convert(input []byte) ([]byte, error) {
	out, err := hdftocsafvex.ConvertHDFToCSAFVEX(input, version)
	if err != nil {
		return nil, fmt.Errorf("hdf-to-csaf-vex conversion failed: %w", err)
	}
	return out, nil
}

func init() {
	RegisterConverter("hdf-amendments", "csaf-vex", &hdfToCSAFVEXConverter{})
}
