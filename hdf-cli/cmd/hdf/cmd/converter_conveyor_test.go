package cmd

import "testing"

func TestConveyorConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "conveyor",
		DisplayName:    "Conveyor to HDF",
		FixtureDir:     "conveyor-to-hdf",
		MinimalFixture: "input/sample-results.json",
		ErrPrefix:      "conveyor conversion failed",
	})
}
