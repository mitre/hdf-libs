package cmd

import netsparker "github.com/mitre/hdf-libs/hdf-converters/v3/converters/netsparker-to-hdf/go"

func init() {
	registerHDFConverterMulti(
		[]string{"netsparker", "invicti"},
		"Netsparker/Invicti to HDF", "netsparker",
		netsparker.ConvertNetsparkerToHDF,
	)
}
