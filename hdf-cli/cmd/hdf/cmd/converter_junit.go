//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	junit "github.com/mitre/hdf-converters/converters/junit-to-hdf/go"
)

type junitConverter struct{}

func (c *junitConverter) Name() string {
	return "JUnit to HDF"
}

func (c *junitConverter) Convert(input []byte) ([]byte, error) {
	result, err := junit.ConvertJUnitToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("junit conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("junit", "hdf", &junitConverter{})
}
