package cmd

import msftdefenderdevops "github.com/mitre/hdf-libs/hdf-converters/converters/msft-defender-devops-to-hdf/go"

func init() {
	registerHDFConverterMulti(
		[]string{"msft-defender-devops", "msdo"},
		"Microsoft Defender for DevOps to HDF",
		"msft-defender-devops",
		msftdefenderdevops.ConvertMsftDefenderDevopsToHDF,
	)
}
