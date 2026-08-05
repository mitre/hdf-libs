package convert

import msftdefenderendpoint "github.com/mitre/hdf-libs/hdf-converters/v3/converters/msft-defender-endpoint-to-hdf/go"

func init() {
	registerHDFConverterMulti(
		[]string{"msft-defender-endpoint", "defender-endpoint"},
		"Microsoft Defender for Endpoint to HDF",
		"msft-defender-endpoint",
		msftdefenderendpoint.ConvertMsftDefenderEndpointToHDF,
	)
}
