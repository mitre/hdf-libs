package cmd

import ckl "github.com/mitre/hdf-libs/hdf-converters/v3/converters/ckl-to-hdf/go"

func init() {
	registerHDFConverter("ckl", "CKL to HDF", "ckl", ckl.ConvertCKLToHDF)
}
