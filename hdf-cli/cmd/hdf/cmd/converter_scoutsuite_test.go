package cmd

import "testing"

func TestScoutSuiteConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "scoutsuite",
		DisplayName:    "ScoutSuite to HDF",
		FixtureDir:     "scoutsuite-to-hdf",
		MinimalFixture: "input/scoutsuite_sample.js",
		ErrPrefix:      "scoutsuite conversion failed",
		InvalidInput:   "not valid json",
	})
}
