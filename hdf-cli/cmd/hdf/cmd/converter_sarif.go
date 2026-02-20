//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	sarif "github.com/mitre/hdf-converters/converters/sarif-to-hdf/go"
)

type sarifConverter struct{}

func (c *sarifConverter) Name() string {
	return "SARIF to HDF"
}

func (c *sarifConverter) Convert(input []byte) ([]byte, error) {
	result, err := sarif.ConvertSarifToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("sarif conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("sarif", "hdf", &sarifConverter{})
}
