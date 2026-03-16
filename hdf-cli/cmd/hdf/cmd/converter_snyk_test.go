package cmd

import "testing"

func TestSnykConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "snyk",
		DisplayName:    "Snyk to HDF",
		FixtureDir:     "snyk-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "snyk conversion failed",
	})
}
