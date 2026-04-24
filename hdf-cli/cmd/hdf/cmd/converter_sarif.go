package cmd

import (
	"encoding/json"
	"fmt"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
)

// versionedSarifConverter wraps the SARIF converter with VersionedConverter
// support, allowing callers to specify which SARIF schema version the input
// conforms to (e.g. "2.0.0" vs "2.1.0").
type versionedSarifConverter struct {
	inputVersion string
}

// Name returns the human-readable name for this converter.
func (c *versionedSarifConverter) Name() string {
	return "SARIF to HDF"
}

// Convert transforms SARIF input to HDF output.
func (c *versionedSarifConverter) Convert(input []byte) ([]byte, error) {
	result, err := sarif.ConvertSarifToHDF(input, version, c.inputVersion)
	if err != nil {
		return nil, fmt.Errorf("sarif conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

// SetInputVersion sets the SARIF schema version of the input.
// An empty string means "use the latest supported version" (2.1.0).
func (c *versionedSarifConverter) SetInputVersion(v string) {
	c.inputVersion = v
}

// SupportedVersions returns the SARIF versions this converter handles,
// latest first.
func (c *versionedSarifConverter) SupportedVersions() []string {
	return []string{"2.1.0", "2.0.0"}
}

func init() {
	RegisterConverter("sarif", "hdf", &versionedSarifConverter{})
}
