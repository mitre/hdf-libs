package convert

import openvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/openvex-to-hdf/go"

func init() {
	registerHDFAmendmentsConverter("openvex", "OpenVEX to HDF Amendments", "openvex", openvex.ConvertOpenVEXToHDF)
}
