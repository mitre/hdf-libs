package cmd

import zap "github.com/mitre/hdf-converters/converters/zap-to-hdf/go"

func init() {
	registerHDFConverter("zap", "OWASP ZAP to HDF", "zap", zap.ConvertZapToHDF)
}
