package cmd

import "testing"

func TestFortifyConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "fortify",
		DisplayName:    "Fortify to HDF",
		FixtureDir:     "fortify-to-hdf",
		MinimalFixture: "input/fortify_webgoat_results.fvdl",
		ErrPrefix:      "fortify conversion failed",
		InvalidInput:   "not valid xml",
	})
}
