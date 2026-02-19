//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	awsconfig "github.com/mitre/hdf-converters/converters/aws-config-to-hdf/go"
)

type awsConfigConverter struct{}

func (c *awsConfigConverter) Name() string {
	return "AWS Config to HDF"
}

func (c *awsConfigConverter) Convert(input []byte) ([]byte, error) {
	result, err := awsconfig.ConvertAWSConfigToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("aws-config conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	RegisterConverter("aws-config", "hdf", &awsConfigConverter{})
}
