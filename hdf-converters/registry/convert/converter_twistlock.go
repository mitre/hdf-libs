package convert

import twistlock "github.com/mitre/hdf-libs/hdf-converters/v3/converters/twistlock-to-hdf/go"

func init() {
	registerHDFConverter("twistlock", "Twistlock to HDF", "twistlock", twistlock.ConvertTwistlockToHDF)
}
