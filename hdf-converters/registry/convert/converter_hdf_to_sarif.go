package convert

import (
	"fmt"

	hdftosarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-sarif/go"
)

type hdfToSARIFConverter struct{}

func (c *hdfToSARIFConverter) Name() string { return "HDF Results to SARIF" }

func (c *hdfToSARIFConverter) Convert(input []byte) ([]byte, error) {
	out, err := hdftosarif.ConvertHDFToSARIF(input, version)
	if err != nil {
		return nil, fmt.Errorf("hdf-to-sarif conversion failed: %w", err)
	}
	return out, nil
}

func init() {
	RegisterConverter("hdf", "sarif", &hdfToSARIFConverter{})
}
