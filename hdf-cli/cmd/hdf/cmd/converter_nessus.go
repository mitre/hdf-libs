package cmd

import (
	"encoding/json"
	"fmt"

	nessus "github.com/mitre/hdf-converters/converters/nessus-to-hdf/go"
)

type nessusConverter struct{}

func (c *nessusConverter) Name() string {
	return "Nessus to HDF"
}

func (c *nessusConverter) Convert(input []byte) ([]byte, error) {
	// Convert to HDF
	result, err := nessus.ConvertNessusToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("nessus conversion failed: %w", err)
	}

	// Serialize to JSON
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("nessus", "hdf", &nessusConverter{})
}
