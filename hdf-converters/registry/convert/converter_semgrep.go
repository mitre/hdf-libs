package convert

import semgrep "github.com/mitre/hdf-libs/hdf-converters/v3/converters/semgrep-to-hdf/go"

func init() {
	registerHDFConverter("semgrep", "Semgrep to HDF", "semgrep", semgrep.ConvertSemgrepToHDF)
}
