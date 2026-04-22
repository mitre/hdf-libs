package cmd

import splunk "github.com/mitre/hdf-libs/hdf-converters/converters/splunk-to-hdf/go"

func init() {
	registerHDFConverter("splunk", "Splunk to HDF", "splunk", splunk.ConvertSplunkToHDF)
}
