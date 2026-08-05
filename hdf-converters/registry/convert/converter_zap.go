package convert

import zap "github.com/mitre/hdf-libs/hdf-converters/v3/converters/zap-to-hdf/go"

func init() {
	registerHDFConverter("zap", "OWASP ZAP to HDF", "zap", zap.ConvertZapToHDF)
}
