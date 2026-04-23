package junit

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestJunitFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "junit-to-hdf",
		Label:       "JUnit",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects testsuites root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<testsuites name="AllTests" tests="10" failures="2">
  <testsuite name="Suite1" tests="5" failures="1">
    <testcase name="test1"/>
  </testsuite>
</testsuites>`,
				Confidence: 1.0,
			},
			{
				Name: "detects testsuite root at confidence 1.0",
				Input: `<?xml version="1.0"?>
<testsuite name="Suite1" tests="5" failures="1">
  <testcase name="test1"/>
</testsuite>`,
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
			{Name: "does not match non-string input", Input: map[string]any{"testsuites": true}},
		},
	})
}
