package cmd

import "testing"

func TestCycloneDXConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "cyclonedx",
		DisplayName:    "CycloneDX to HDF",
		FixtureDir:     "cyclonedx-to-hdf",
		MinimalFixture: "input/minimal-vulns.json",
		ErrPrefix:      "cyclonedx conversion failed",
	})
}
