package xccdf

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestXccdfFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "xccdf-results-to-hdf",
		Label:       "XCCDF/ARF",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects Benchmark root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_benchmark_1">
  <status>accepted</status>
  <Rule id="rule_1"><title>Test Rule</title></Rule>
</Benchmark>`,
				Confidence: 1.0,
			},
			{
				Name: "detects namespaced Benchmark at confidence 1.0",
				Input: `<?xml version="1.0"?>
<xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_benchmark_1">
  <xccdf:status>accepted</xccdf:status>
</xccdf:Benchmark>`,
				Confidence: 1.0,
			},
			{
				Name: "detects asset-report-collection root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1">
  <report-requests/>
  <assets/>
  <reports/>
</asset-report-collection>`,
				Confidence: 1.0,
			},
			{
				Name: "detects namespaced asset-report-collection at confidence 1.0",
				Input: `<?xml version="1.0"?>
<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1">
  <arf:report-requests/>
</arf:asset-report-collection>`,
				Confidence: 1.0,
			},
		},
		Negative: []fptest.DetectionCase{
			{
				Name: "does not match different XML format",
				Input: `<?xml version="1.0"?>
<FVDL xmlns="xmlns.fortify.com/schema/fvdl" version="1.12">
  <Build/>
</FVDL>`,
			},
			{Name: "does not match non-string input", Input: map[string]any{"Benchmark": true}},
		},
	})
}
