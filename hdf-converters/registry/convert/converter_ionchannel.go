package convert

import ionchannel "github.com/mitre/hdf-libs/hdf-converters/v3/converters/ionchannel-to-hdf/go"

func init() {
	registerHDFConverter("ionchannel", "Ion Channel to HDF", "ionchannel", ionchannel.ConvertIonChannelToHDF)
}
