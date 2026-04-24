package cmd

import trufflehog "github.com/mitre/hdf-libs/hdf-converters/v3/converters/trufflehog-to-hdf/go"

func init() {
	registerHDFConverter("trufflehog", "TruffleHog to HDF", "trufflehog", trufflehog.ConvertTrufflehogToHDF)
}
