package cmd

import (
	"encoding/json"
	"fmt"

	legacyhdf "github.com/mitre/hdf-libs/hdf-converters/converters/legacyhdf-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
)

// legacyHDFConverter converts legacy InSpec exec-json (profiles/controls)
// to the current HDF format (baselines/requirements).
type legacyHDFConverter struct{}

// Name returns the human-readable name for this converter.
func (c *legacyHDFConverter) Name() string {
	return "Legacy InSpec exec-json to HDF"
}

// Convert transforms legacy InSpec exec-json input to current HDF output.
func (c *legacyHDFConverter) Convert(input []byte) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "legacyhdf", 0); err != nil {
		return nil, fmt.Errorf("legacyhdf input validation: %w", err)
	}

	if !legacyhdf.IsHDFV1(input) {
		return nil, fmt.Errorf("input is not valid legacy InSpec exec-json format")
	}

	var v1 legacyhdf.HDFV1Results
	if err := json.Unmarshal(input, &v1); err != nil {
		return nil, fmt.Errorf("failed to parse legacy InSpec input: %w", err)
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
