package convert

import (
	"fmt"

	hdftocyclonedxvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-cyclonedx-vex/go"
)

type hdfToCycloneDXVEXConverter struct{}

func (c *hdfToCycloneDXVEXConverter) Name() string { return "HDF Amendments to CycloneDX VEX" }

func (c *hdfToCycloneDXVEXConverter) Convert(input []byte) ([]byte, error) {
	out, err := hdftocyclonedxvex.ConvertHDFToCycloneDXVEX(input, version)
	if err != nil {
		return nil, fmt.Errorf("hdf-to-cyclonedx-vex conversion failed: %w", err)
	}
	return out, nil
}

func init() {
	RegisterConverter("hdf-amendments", "cyclonedx-vex", &hdfToCycloneDXVEXConverter{})
}
