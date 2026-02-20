//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	gosec "github.com/mitre/hdf-converters/converters/gosec-to-hdf/go"
)

type gosecConverter struct{}

func (c *gosecConverter) Name() string {
	return "gosec to HDF"
}

func (c *gosecConverter) Convert(input []byte) ([]byte, error) {
	result, err := gosec.ConvertGosecToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("gosec conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("gosec", "hdf", &gosecConverter{})
}
