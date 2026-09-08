package convert

import (
	"encoding/json"
	"fmt"

	legacyhdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/legacyhdf-to-hdf/go"
)

// legacyHDFConverter converts InSpec exec-json (the legacy HDF v2 format:
// profiles/controls, the shape Heimdall2 loads) to the current HDF format
// (v3: baselines/requirements).
type legacyHDFConverter struct{}

// Name returns the human-readable name for this converter.
func (c *legacyHDFConverter) Name() string {
	return "InSpec exec-json to HDF"
}

// legacyhdf.ExpectedRequirementCount is deliberately not declared here yet:
// the CLI checks fidelity on the post-processed output, and `--to hdf@2`
// downgrades to the profiles/controls shape it cannot count. Declare it once
// the CLI counts the pre-downgrade document.

// Convert transforms InSpec exec-json input to current HDF output.
func (c *legacyHDFConverter) Convert(input []byte) ([]byte, error) {
	v1, err := legacyhdf.ParseLegacyHDF(input)
	if err != nil {
		return nil, err
	}

	v2 := legacyhdf.ConvertLegacyHDF(v1, version)

	output, err := json.MarshalIndent(v2, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

// ExpectedRequirementCount implements RequirementCountExpecter through the
// package's own overlay-flattening relation.
func (c *legacyHDFConverter) ExpectedRequirementCount(input []byte) (int, string, error) {
	return legacyhdf.ExpectedRequirementCount(input)
}

func init() {
	converter := &legacyHDFConverter{}
	RegisterConverter("legacyhdf", "hdf", converter)
	RegisterConverter("inspec", "hdf", converter)
}
