package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/mitre/hdf-libs/hdf-converters/shared/go/hdfversion"
)

// hdfVersionConverter handles HDF version transforms (e.g. hdf@1 → hdf@2).
// It auto-detects the input version when not specified and transforms to
// the target version.
type hdfVersionConverter struct {
	fromVersion string
	toVersion   string
}

// Name returns the human-readable name for this converter.
func (c *hdfVersionConverter) Name() string {
	from := c.fromVersion
	if from == "" {
		from = "auto"
	}
	to := c.toVersion
	if to == "" {
		to = "2"
	}
	return fmt.Sprintf("HDF v%s to HDF v%s", from, to)
}

// Convert transforms HDF data between schema versions.
func (c *hdfVersionConverter) Convert(input []byte) ([]byte, error) {
	fromVer := c.fromVersion

	// If fromVersion is empty, auto-detect from input
	if fromVer == "" {
		detected, err := hdfversion.DetectHDFVersion(input)
		if err != nil {
			return nil, fmt.Errorf("HDF version detection failed: %w", err)
		}
		fromVer = detected
	}

	toVer := c.toVersion
	if toVer == "" {
		toVer = "2" // default target is latest
	}

	if fromVer == toVer {
		return input, nil
	}

	output, err := hdfversion.TransformHDF(input, fromVer, toVer)
	if err != nil {
		return nil, fmt.Errorf("HDF version transform failed: %w", err)
	}

	// Lossy transform warning for downgrades
	fromNum, _ := strconv.Atoi(fromVer)
	toNum, _ := strconv.Atoi(toVer)
	if fromNum > toNum {
		fmt.Fprintln(os.Stderr, "Warning: HDF version downgrade is a lossy conversion. Some fields have no equivalent in the target version.")
	}

	return output, nil
}

// SetInputVersion sets the source HDF version.
func (c *hdfVersionConverter) SetInputVersion(v string) {
	c.fromVersion = v
}

// SupportedVersions returns the HDF versions this converter handles.
func (c *hdfVersionConverter) SupportedVersions() []string {
	return []string{"2", "1"}
}

// SetOutputVersion sets the target HDF version for the transform.
func (c *hdfVersionConverter) SetOutputVersion(v string) {
	c.toVersion = v
}

func init() {
	// Register hdf→hdf converter for explicit version transforms
	// (e.g. --from hdf@1 --to hdf@2, or --from hdf@1 --to hdf).
	RegisterConverter("hdf", "hdf", &hdfVersionConverter{
		toVersion: "2", // default target is latest
	})
}

// PostProcessToVersion applies HDF version downgrade to converter output.
// Used when --to hdf@1 is combined with a non-HDF source format.
// Returns the input unchanged if toVersion is empty or "2" (current default).
func PostProcessToVersion(output []byte, toVersion string) ([]byte, error) {
	if toVersion == "" || toVersion == "2" {
		return output, nil
	}

	result, err := hdfversion.TransformHDF(output, "2", toVersion)
	if err != nil {
		return nil, fmt.Errorf("HDF version post-processing failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Warning: HDF version downgrade is a lossy conversion. Some fields have no equivalent in the target version.")
	return result, nil
}
