package cmd

import trufflehog "github.com/mitre/hdf-libs/hdf-converters/converters/trufflehog-to-hdf/go"

func init() {
	registerHDFConverter("trufflehog", "TruffleHog to HDF", "trufflehog", trufflehog.ConvertTrufflehogToHDF)
}
