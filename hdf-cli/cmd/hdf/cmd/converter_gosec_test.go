package cmd

import "testing"

func TestGosecConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "gosec",
		DisplayName:    "gosec to HDF",
		FixtureDir:     "gosec-to-hdf",
		MinimalFixture: "input/real.json",
		ErrPrefix:      "gosec conversion failed",
	})
}
