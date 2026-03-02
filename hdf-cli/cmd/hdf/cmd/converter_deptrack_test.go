package cmd

import "testing"

func TestDeptrackConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "deptrack",
		DisplayName:    "Dependency-Track to HDF",
		FixtureDir:     "deptrack-to-hdf",
		MinimalFixture: "input/fpf-default.json",
		ErrPrefix:      "deptrack conversion failed",
	})
}

func TestDependencyTrackAliasConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "dependency-track",
		DisplayName:    "Dependency-Track to HDF",
		FixtureDir:     "deptrack-to-hdf",
		MinimalFixture: "input/fpf-default.json",
		ErrPrefix:      "deptrack conversion failed",
	})
}
