package cmd

import xccdf "github.com/mitre/hdf-converters/converters/xccdf-results-to-hdf/go"

func init() {
	// xccdf — Auto-detect: benchmark → baseline, results → results
	registerRawConverter(
		"xccdf",
		"XCCDF to HDF (auto-detect)", "xccdf",
		func(input []byte, converterVersion string) ([]byte, error) {
			output, _, err := xccdf.ConvertXccdfToHDF(input, converterVersion)
			return output, err
		},
	)

	// xccdf-benchmark — Require benchmark input, produce baseline
	registerHDFBaselineConverter(
		"xccdf-benchmark",
		"XCCDF Benchmark to HDF Baseline", "xccdf-benchmark",
		xccdf.ConvertXccdfBenchmarkToHDF,
	)

	// xccdf-results — Require results input (TestResult elements)
	registerHDFConverter(
		"xccdf-results",
		"XCCDF Results to HDF", "xccdf-results",
		xccdf.ConvertXccdfResultsToHDF,
	)

	// arf — ARF 1.1 (always results)
	registerHDFConverter(
		"arf",
		"ARF to HDF", "arf",
		xccdf.ConvertXccdfResultsToHDF,
	)
}
