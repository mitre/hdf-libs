package convert

import (
	"encoding/json"
	"fmt"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
)

// versionedSarifConverter wraps the SARIF converter with VersionedConverter
// support, so a caller can state which SARIF schema version the input conforms to.
// Only 2.1.0 is supported; any other explicit version is refused rather than
// silently ignored.
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

// ExpectedRequirementCount implements RequirementCountExpecter with the
// converter's own grouping, honoring the selected input version.
func (c *versionedSarifConverter) ExpectedRequirementCount(input []byte) (int, string, error) {
	return sarif.ExpectedRequirementCount(input, c.inputVersion)
}

// SetInputVersion sets the SARIF schema version of the input.
// An empty string means "use the latest supported version" (2.1.0).
func (c *versionedSarifConverter) SetInputVersion(v string) {
	c.inputVersion = v
}

// SupportedVersions returns the SARIF versions this converter handles. 2.1.0 is the
// only one: it is the OASIS Standard and the single value the vendored schema's
// version enum admits. The 2.0 committee draft was listed here while the converter
// could not in fact process it, so a library consumer was told 2.0 worked and then
// refused.
func (c *versionedSarifConverter) SupportedVersions() []string {
	return []string{"2.1.0"}
}

func init() {
	RegisterConverter("sarif", "hdf", &versionedSarifConverter{})
}
