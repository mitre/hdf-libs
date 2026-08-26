package convert

import trufflehog "github.com/mitre/hdf-libs/hdf-converters/v3/converters/trufflehog-to-hdf/go"

func init() {
	// A clean TruffleHog scan emits empty stdout; accept it as zero findings.
	registerHDFConverter("trufflehog", "TruffleHog to HDF", "trufflehog", trufflehog.ConvertTrufflehogToHDF, WithEmptyInputOK())
}
