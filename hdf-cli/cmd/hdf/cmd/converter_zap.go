//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	zap "github.com/mitre/hdf-converters/converters/zap-to-hdf/go"
)

type zapConverter struct{}

func (c *zapConverter) Name() string {
	return "OWASP ZAP to HDF"
}

func (c *zapConverter) Convert(input []byte) ([]byte, error) {
	result, err := zap.ConvertZapToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("zap conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("zap", "hdf", &zapConverter{})
}
