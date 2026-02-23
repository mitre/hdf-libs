//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	xccdf "github.com/mitre/hdf-converters/converters/xccdf-results-to-hdf/go"
)

type xccdfConverter struct{}

func (c *xccdfConverter) Name() string {
	return "XCCDF/ARF to HDF"
}

func (c *xccdfConverter) Convert(input []byte) ([]byte, error) {
	result, err := xccdf.ConvertXccdfResultsToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("xccdf conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	converter := &xccdfConverter{}
	RegisterConverter("xccdf", "hdf", converter)
	RegisterConverter("arf", "hdf", converter)
}
