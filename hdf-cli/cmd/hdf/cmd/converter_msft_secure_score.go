package cmd

import msftsecurescore "github.com/mitre/hdf-libs/hdf-converters/converters/msft-secure-score-to-hdf/go"

func init() {
	registerHDFConverter("msft-secure-score", "Microsoft Secure Score to HDF", "msft-secure-score", msftsecurescore.ConvertMsftSecureScoreToHDF)
}
