package cmd

import (
	"encoding/json"
	"fmt"

	legacyhdf "github.com/mitre/hdf-converters/converters/legacyhdf-to-hdf/go"
)

// legacyHDFConverter converts HDF v1.0 (legacy InSpec JSON) to HDF v2.0.
type legacyHDFConverter struct{}

// Name returns the human-readable name for this converter.
func (c *legacyHDFConverter) Name() string {
	return "Legacy HDF (v1.0) to HDF (v2.0)"
}

// Convert transforms HDF v1.0 input to HDF v2.0 output.
func (c *legacyHDFConverter) Convert(input []byte) ([]byte, error) {
	// Validate input is v1.0 format
	if !legacyhdf.IsHDFV1(input) {
		return nil, fmt.Errorf("input is not valid HDF v1.0 format")
	}

	// Parse v1.0 input
	var v1 legacyhdf.HDFV1Results
	if err := json.Unmarshal(input, &v1); err != nil {
		return nil, fmt.Errorf("failed to parse HDF v1.0 input: %w", err)
	}

	// Convert to v2.0
	v2 := legacyhdf.ConvertV1ToV2(&v1)

	// Serialize v2.0 output
	output, err := json.MarshalIndent(v2, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF v2.0 output: %w", err)
	}

	return output, nil
}

func init() {
	converter := &legacyHDFConverter{}
	RegisterConverter("legacyhdf", "hdf", converter)
	RegisterConverter("inspec", "hdf", converter)
}
