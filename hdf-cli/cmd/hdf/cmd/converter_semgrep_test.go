package cmd

import "testing"

func TestSemgrepConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "semgrep",
		DisplayName:    "Semgrep to HDF",
		FixtureDir:     "semgrep-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "semgrep conversion failed",
	})
}
