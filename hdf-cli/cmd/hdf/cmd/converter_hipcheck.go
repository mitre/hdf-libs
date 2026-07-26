package cmd

import hipcheck "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hipcheck-to-hdf/go"

func init() {
	registerHDFConverter("hipcheck", "Hipcheck to HDF", "hipcheck", hipcheck.ConvertHipcheckToHDF)
}
