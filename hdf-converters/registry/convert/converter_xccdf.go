package convert

import xccdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/xccdf-results-to-hdf/go"

func init() {
	// xccdf — Auto-detect: benchmark → baseline, results → results.
	registerRawConverter("xccdf", "XCCDF to HDF (auto-detect)", "xccdf",
		func(input []byte, converterVersion string) ([]byte, error) {
			output, _, err := xccdf.ConvertXccdfToHDF(input, converterVersion)
			return output, err
		},
		WithExpectedRequirementCount(xccdf.ExpectedAutoDetectRequirementCount),
	)

	// xccdf-benchmark — Require benchmark input, produce baseline
	registerHDFBaselineConverter(
		"xccdf-benchmark",
		"XCCDF Benchmark to HDF Baseline", "xccdf-benchmark",
		xccdf.ConvertXccdfBenchmarkToHDF,
		WithExpectedRequirementCount(xccdf.ExpectedBenchmarkRequirementCount),
	)

	// xccdf-results — Require results input (TestResult elements)
	registerHDFConverter(
		"xccdf-results",
		"XCCDF Results to HDF", "xccdf-results",
		xccdf.ConvertXccdfResultsToHDF,
		WithExpectedRequirementCount(xccdf.ExpectedRequirementCount),
	)

	// arf — ARF 1.1 (always results)
	registerHDFConverter(
		"arf",
		"ARF to HDF", "arf",
		xccdf.ConvertXccdfResultsToHDF,
		WithExpectedRequirementCount(xccdf.ExpectedRequirementCount),
	)
}
