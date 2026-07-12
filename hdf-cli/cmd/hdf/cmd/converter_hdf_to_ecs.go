package cmd

import (
	hdftoecs "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ecs/go"
)

type hdfToECSConverter struct{}

func (c *hdfToECSConverter) Name() string {
	return "HDF Results to ECS"
}

func (c *hdfToECSConverter) Convert(input []byte) ([]byte, error) {
	return hdftoecs.ConvertHDFToECS(input, version)
}

func init() {
	RegisterConverter("hdf", "ecs", &hdfToECSConverter{})
}
