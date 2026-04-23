package cmd

import msftdefendercloud "github.com/mitre/hdf-libs/hdf-converters/converters/msft-defender-cloud-to-hdf/go"

func init() {
	registerHDFConverterMulti(
		[]string{"msft-defender-cloud", "defender-cloud"},
		"Microsoft Defender for Cloud to HDF",
		"msft-defender-cloud",
		msftdefendercloud.ConvertMsftDefenderCloudToHDF,
	)
}
