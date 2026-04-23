package cmd

import grype "github.com/mitre/hdf-libs/hdf-converters/converters/grype-to-hdf/go"

func init() {
	registerHDFConverter("grype", "Grype to HDF", "grype", grype.ConvertGrypeToHDF)
}
