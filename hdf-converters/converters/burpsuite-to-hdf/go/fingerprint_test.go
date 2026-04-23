package burpsuite

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestBurpsuiteFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "burpsuite-to-hdf",
		Label:       "Burp Suite",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects BurpSuite XML with burpVersion at confidence 1.0",
				Input: `<?xml version="1.0"?>
<issues burpVersion="2023.1.2" exportTime="Thu Jan 01 00:00:00 UTC 2023">
  <issue><serialNumber>1234</serialNumber></issue>
</issues>`,
				Confidence: 1.0,
			},
			{
				Name: "detects issues root without burpVersion at confidence 0.7",
				Input: `<?xml version="1.0"?>
<issues>
  <issue><serialNumber>1234</serialNumber></issue>
</issues>`,
				Confidence: 0.7,
			},
		},
		Negative: []fptest.DetectionCase{
			{
				Name: "does not match different XML format",
				Input: `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="scan"><ReportHost name="host1"></ReportHost></Report>
</NessusClientData_v2>`,
			},
			{Name: "does not match non-string input", Input: map[string]any{"issues": true}},
		},
	})
}
