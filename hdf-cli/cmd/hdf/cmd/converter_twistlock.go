package cmd

import twistlock "github.com/mitre/hdf-converters/converters/twistlock-to-hdf/go"

func init() {
	registerHDFConverter("twistlock", "Twistlock to HDF", "twistlock", twistlock.ConvertTwistlockToHDF)
}
