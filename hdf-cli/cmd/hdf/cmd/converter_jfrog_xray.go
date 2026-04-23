package cmd

import jfrogxray "github.com/mitre/hdf-libs/hdf-converters/converters/jfrog-xray-to-hdf/go"

func init() {
	registerHDFConverter("jfrog-xray", "JFrog Xray to HDF", "jfrog-xray", jfrogxray.ConvertJfrogXrayToHDF)
	registerHDFConverter("xray", "JFrog Xray to HDF", "jfrog-xray", jfrogxray.ConvertJfrogXrayToHDF)
}
