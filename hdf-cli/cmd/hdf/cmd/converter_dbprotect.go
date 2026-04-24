package cmd

import dbprotect "github.com/mitre/hdf-libs/hdf-converters/v3/converters/dbprotect-to-hdf/go"

func init() {
	registerHDFConverter("dbprotect", "DBProtect to HDF", "dbprotect", dbprotect.ConvertDbprotectToHDF)
}
