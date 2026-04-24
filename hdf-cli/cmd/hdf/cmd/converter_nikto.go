package cmd

import nikto "github.com/mitre/hdf-libs/hdf-converters/v3/converters/nikto-to-hdf/go"

func init() {
	registerHDFConverter("nikto", "Nikto to HDF", "nikto", nikto.ConvertNiktoToHDF)
}
