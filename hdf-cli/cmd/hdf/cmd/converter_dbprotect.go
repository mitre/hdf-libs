package cmd

import dbprotect "github.com/mitre/hdf-converters/converters/dbprotect-to-hdf/go"

func init() {
	registerHDFConverter("dbprotect", "DBProtect to HDF", "dbprotect", dbprotect.ConvertDbprotectToHDF)
}
