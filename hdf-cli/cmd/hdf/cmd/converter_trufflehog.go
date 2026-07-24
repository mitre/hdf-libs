package cmd

import trufflehog "github.com/mitre/hdf-libs/hdf-converters/v3/converters/trufflehog-to-hdf/go"

func init() {
	// TruffleHog is exit-code-first: a clean scan emits no report (empty stdout).
	// WithEmptyInputOK lets `hdf convert --from trufflehog` accept that as zero
	// findings instead of erroring on empty input. See card hdf-libs-iow3.
	registerHDFConverter("trufflehog", "TruffleHog to HDF", "trufflehog", trufflehog.ConvertTrufflehogToHDF, WithEmptyInputOK())
}
