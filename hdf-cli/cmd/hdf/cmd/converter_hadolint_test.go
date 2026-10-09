package cmd

import "testing"

func TestHadolintConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "hadolint",
		DisplayName:    "hadolint to HDF",
		FixtureDir:     "hadolint-to-hdf",
		MinimalFixture: "input/real.json",
		ErrPrefix:      "hadolint conversion failed",
	})
}
