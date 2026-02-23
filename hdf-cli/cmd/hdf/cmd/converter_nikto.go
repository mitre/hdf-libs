//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	nikto "github.com/mitre/hdf-converters/converters/nikto-to-hdf/go"
)

type niktoConverter struct{}

func (c *niktoConverter) Name() string {
	return "Nikto to HDF"
}

func (c *niktoConverter) Convert(input []byte) ([]byte, error) {
	result, err := nikto.ConvertNiktoToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("nikto conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("nikto", "hdf", &niktoConverter{})
}
