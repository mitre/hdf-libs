package cmd

import (
	hdftocsv "github.com/mitre/hdf-libs/hdf-converters/converters/hdf-to-csv/go"
)

type hdfToCSVConverter struct{}

func (c *hdfToCSVConverter) Name() string {
	return "HDF to CSV"
}

func (c *hdfToCSVConverter) Convert(input []byte) ([]byte, error) {
	return hdftocsv.ConvertHDFToCSV(input)
}

func init() {
	RegisterConverter("hdf", "csv", &hdfToCSVConverter{})
}
