package fortify

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestFortifyFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "fortify-to-hdf",
		Label:       "Fortify",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects Fortify FVDL with namespace at confidence 1.0",
				Input: `<?xml version="1.0"?>
<FVDL xmlns="xmlns.fortify.com/schema/fvdl" version="1.12">
  <Build><SourceFiles><File size="1234" type="java"/></SourceFiles></Build>
</FVDL>`,
				Confidence: 1.0,
			},
			{
				Name: "detects FVDL without Fortify namespace at confidence 0.95",
				Input: `<?xml version="1.0"?>
<FVDL version="1.12">
  <Build><SourceFiles><File size="1234" type="java"/></SourceFiles></Build>
</FVDL>`,
				Confidence: 0.95,
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
			{Name: "does not match non-string input", Input: map[string]any{"FVDL": true}},
		},
	})
}
