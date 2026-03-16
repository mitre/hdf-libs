package cmd

import nikto "github.com/mitre/hdf-converters/converters/nikto-to-hdf/go"

func init() {
	registerHDFConverter("nikto", "Nikto to HDF", "nikto", nikto.ConvertNiktoToHDF)
}
