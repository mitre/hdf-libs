//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	sonarqube "github.com/mitre/hdf-converters/converters/sonarqube-to-hdf/go"
)

type sonarqubeConverter struct{}

func (c *sonarqubeConverter) Name() string {
	return "SonarQube to HDF"
}

func (c *sonarqubeConverter) Convert(input []byte) ([]byte, error) {
	result, err := sonarqube.ConvertSonarqubeToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("sonarqube conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("sonarqube", "hdf", &sonarqubeConverter{})
}
