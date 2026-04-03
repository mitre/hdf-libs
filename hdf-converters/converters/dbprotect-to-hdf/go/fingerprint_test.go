package dbprotect

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestDbprotectFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "dbprotect-to-hdf",
		Label:       "DBProtect",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects DBProtect XML with metadata and data at confidence 1.0",
				Input: `<?xml version="1.0"?>
<dataset>
  <metadata><item name="col1" type="string"/></metadata>
  <data><row><value>cell1</value></row></data>
</dataset>`,
				Confidence: 1.0,
			},
			{
				Name: "detects dataset root without metadata/data at confidence 0.8",
				Input: `<?xml version="1.0"?>
<dataset>
  <other>content</other>
</dataset>`,
				Confidence: 0.8,
			},
		},
		Negative: []fptest.DetectionCase{
			{
				Name: "does not match different XML format",
				Input: `<?xml version="1.0"?>
<testsuites>
  <testsuite name="test"><testcase name="case1"/></testsuite>
</testsuites>`,
			},
			{Name: "does not match non-string input", Input: map[string]any{"dataset": true}},
		},
	})
}
