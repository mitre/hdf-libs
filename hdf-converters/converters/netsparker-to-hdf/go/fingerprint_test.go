package netsparker

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestNetsparkerFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "netsparker-to-hdf",
		Label:       "Netsparker",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects netsparker-enterprise root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<netsparker-enterprise>
  <target><url>https://example.com</url></target>
  <vulnerabilities/>
</netsparker-enterprise>`,
				Confidence: 1.0,
			},
			{
				Name: "detects invicti-enterprise root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<invicti-enterprise>
  <target><url>https://example.com</url></target>
  <vulnerabilities/>
</invicti-enterprise>`,
				Confidence: 1.0,
			},
		},
		Negative: []fptest.DetectionCase{
			{
				Name: "does not match different XML format",
				Input: `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="scan"/>
</NessusClientData_v2>`,
			},
			{Name: "does not match non-string input", Input: map[string]any{"netsparker": true}},
		},
	})
}
