//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	cyclonedx "github.com/mitre/hdf-converters/converters/cyclonedx-to-hdf/go"
)

type cyclonedxConverter struct{}

func (c *cyclonedxConverter) Name() string {
	return "CycloneDX to HDF"
}

func (c *cyclonedxConverter) Convert(input []byte) ([]byte, error) {
	result, err := cyclonedx.ConvertCycloneDXToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("cyclonedx conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("cyclonedx", "hdf", &cyclonedxConverter{})
}
