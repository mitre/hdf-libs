package nessus

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestNessusFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "nessus-to-hdf",
		Label:       "Nessus",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects NessusClientData_v2 at confidence 1.0",
				Input: `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="scan">
    <ReportHost name="host1">
      <ReportItem pluginID="12345"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>`,
				Confidence: 1.0,
			},
		},
		Negative: []fptest.DetectionCase{
			{
				Name: "does not match different XML format",
				Input: `<?xml version="1.0"?>
<testsuites>
  <testsuite name="Suite1"><testcase name="test1"/></testsuite>
</testsuites>`,
			},
			{Name: "does not match non-string input", Input: map[string]any{"NessusClientData_v2": true}},
		},
	})
}
