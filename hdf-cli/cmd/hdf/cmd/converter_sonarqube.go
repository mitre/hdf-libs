package cmd

import (
	"fmt"

	sonarqube "github.com/mitre/hdf-converters/converters/sonarqube-to-hdf/go"
)

type sonarqubeConverter struct{}

func (c *sonarqubeConverter) Name() string {
	return "SonarQube to HDF"
}

func (c *sonarqubeConverter) Convert(input []byte) ([]byte, error) {
	// Convert to HDF (already returns JSON bytes)
	output, err := sonarqube.ConvertSonarqubeToHDF(input)
	if err != nil {
		return nil, fmt.Errorf("sonarqube conversion failed: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("sonarqube", "hdf", &sonarqubeConverter{})
}
