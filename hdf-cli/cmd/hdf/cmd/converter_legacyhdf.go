package cmd

import (
	"encoding/json"
	"fmt"

	legacyhdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/legacyhdf-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
)

// legacyHDFConverter converts InSpec exec-json (the legacy HDF v2 format:
// profiles/controls, the shape Heimdall2 loads) to the current HDF format
// (v3: baselines/requirements).
type legacyHDFConverter struct{}

// Name returns the human-readable name for this converter.
func (c *legacyHDFConverter) Name() string {
	return "InSpec exec-json to HDF"
}

// Convert transforms InSpec exec-json input to current HDF output.
func (c *legacyHDFConverter) Convert(input []byte) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "legacyhdf", 0); err != nil {
		return nil, fmt.Errorf("legacyhdf input validation: %w", err)
	}

	if !legacyhdf.IsHDFV1(input) {
		return nil, fmt.Errorf("input is not valid InSpec exec-json format")
	}

	var v1 legacyhdf.HDFV1Results
	if err := json.Unmarshal(input, &v1); err != nil {
		return nil, fmt.Errorf("failed to parse InSpec input: %w", err)
	}

	v2 := legacyhdf.ConvertV1ToV2(&v1)

	output, err := json.MarshalIndent(v2, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	converter := &legacyHDFConverter{}
	RegisterConverter("legacyhdf", "hdf", converter)
	RegisterConverter("inspec", "hdf", converter)
}
