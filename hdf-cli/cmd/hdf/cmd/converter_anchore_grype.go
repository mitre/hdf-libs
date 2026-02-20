//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	anchore_grype "github.com/mitre/hdf-converters/converters/anchore-grype-to-hdf/go"
)

type anchoreGrypeConverter struct{}

func (c *anchoreGrypeConverter) Name() string {
	return "Anchore Grype to HDF"
}

func (c *anchoreGrypeConverter) Convert(input []byte) ([]byte, error) {
	result, err := anchore_grype.ConvertAnchoreGrypeToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("anchore grype conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("anchore-grype", "hdf", &anchoreGrypeConverter{})
}
