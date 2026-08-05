package convert

import (
	"fmt"

	hdftoopenvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-openvex/go"
)

type hdfToOpenVEXConverter struct{}

func (c *hdfToOpenVEXConverter) Name() string { return "HDF Amendments to OpenVEX" }

func (c *hdfToOpenVEXConverter) Convert(input []byte) ([]byte, error) {
	out, err := hdftoopenvex.ConvertHDFToOpenVEX(input, version)
	if err != nil {
		return nil, fmt.Errorf("hdf-to-openvex conversion failed: %w", err)
	}
	return out, nil
}

func init() {
	RegisterConverter("hdf-amendments", "openvex", &hdfToOpenVEXConverter{})
}
