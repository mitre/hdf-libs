package cmd

import "testing"

func TestNiktoConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "nikto",
		DisplayName:    "Nikto to HDF",
		FixtureDir:     "nikto-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "nikto conversion failed",
	})
}
