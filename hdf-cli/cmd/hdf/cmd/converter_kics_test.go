package cmd

import "testing"

func TestKicsConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "kics",
		DisplayName:    "KICS to HDF",
		FixtureDir:     "kics-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "kics conversion failed",
	})
}
