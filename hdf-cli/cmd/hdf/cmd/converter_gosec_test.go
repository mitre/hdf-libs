package cmd

import "testing"

func TestGosecConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "gosec",
		DisplayName:    "gosec to HDF",
		FixtureDir:     "gosec-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "gosec conversion failed",
	})
}
