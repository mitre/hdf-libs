//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	grype "github.com/mitre/hdf-converters/converters/grype-to-hdf/go"
)

type grypeConverter struct{}

func (c *grypeConverter) Name() string {
	return "Grype to HDF"
}

func (c *grypeConverter) Convert(input []byte) ([]byte, error) {
	result, err := grype.ConvertGrypeToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("grype conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("grype", "hdf", &grypeConverter{})
}
