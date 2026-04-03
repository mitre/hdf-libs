package veracode

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestVeracodeFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "veracode-to-hdf",
		Label:       "Veracode",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects detailedreport root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0" report_format_version="1.5.0">
  <severity level="5"><category categoryname="SQL Injection"/></severity>
</detailedreport>`,
				Confidence: 1.0,
			},
			{
				Name: "detects namespaced detailedreport at confidence 1.0",
				Input: `<?xml version="1.0"?>
<ns:detailedreport xmlns:ns="https://www.veracode.com/schema/reports/export/1.0">
  <ns:severity level="5"/>
</ns:detailedreport>`,
				Confidence: 1.0,
			},
		},
		Negative: []fptest.DetectionCase{
			{
				Name: "does not match summaryreport",
				Input: `<?xml version="1.0"?>
<summaryreport xmlns="https://www.veracode.com/schema/reports/export/1.0">
  <severity level="5"/>
</summaryreport>`,
			},
			{
				Name: "does not match different XML format",
				Input: `<?xml version="1.0"?>
<testsuites>
  <testsuite name="Suite1"><testcase name="test1"/></testsuite>
</testsuites>`,
			},
			{Name: "does not match non-string input", Input: map[string]any{"detailedreport": true}},
		},
	})
}
