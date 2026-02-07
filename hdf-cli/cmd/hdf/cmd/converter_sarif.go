package cmd

import (
	"fmt"

	sarif "github.com/mitre/hdf-converters/converters/sarif-to-hdf/go"
)

type sarifConverter struct{}

func (c *sarifConverter) Name() string {
	return "SARIF to HDF"
}

func (c *sarifConverter) Convert(input []byte) ([]byte, error) {
	// Convert to HDF (already returns JSON bytes)
	output, err := sarif.ConvertSarifToHDF(input)
	if err != nil {
		return nil, fmt.Errorf("sarif conversion failed: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("sarif", "hdf", &sarifConverter{})
}
