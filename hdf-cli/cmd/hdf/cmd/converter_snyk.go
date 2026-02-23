//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	snyk "github.com/mitre/hdf-converters/converters/snyk-to-hdf/go"
)

type snykConverter struct{}

func (c *snykConverter) Name() string {
	return "Snyk to HDF"
}

func (c *snykConverter) Convert(input []byte) ([]byte, error) {
	result, err := snyk.ConvertSnykToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("snyk conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("snyk", "hdf", &snykConverter{})
}
