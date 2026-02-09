package cmd

import (
	"fmt"

	anchore_grype "github.com/mitre/hdf-converters/converters/anchore-grype-to-hdf/go"
)

type anchoreGrypeConverter struct{}

func (c *anchoreGrypeConverter) Name() string {
	return "Anchore Grype to HDF"
}

func (c *anchoreGrypeConverter) Convert(input []byte) ([]byte, error) {
	// Convert to HDF (already returns JSON bytes)
	output, err := anchore_grype.ConvertAnchoreGrypeToHDF(input)
	if err != nil {
		return nil, fmt.Errorf("anchore grype conversion failed: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("anchore-grype", "hdf", &anchoreGrypeConverter{})
}
