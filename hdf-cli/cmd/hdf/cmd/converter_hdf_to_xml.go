package cmd

import (
	hdftoxml "github.com/mitre/hdf-converters/converters/hdf-to-xml/go"
)

type hdfToXMLConverter struct{}

func (c *hdfToXMLConverter) Name() string {
	return "HDF to XML"
}

func (c *hdfToXMLConverter) Convert(input []byte) ([]byte, error) {
	return hdftoxml.ConvertHDFToXML(input)
}

func init() {
	RegisterConverter("hdf", "xml", &hdfToXMLConverter{})
}
