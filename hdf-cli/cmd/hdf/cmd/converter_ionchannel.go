package cmd

import ionchannel "github.com/mitre/hdf-libs/hdf-converters/converters/ionchannel-to-hdf/go"

func init() {
	registerHDFConverter("ionchannel", "Ion Channel to HDF", "ionchannel", ionchannel.ConvertIonChannelToHDF)
}
