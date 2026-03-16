package cmd

import "testing"

func TestJunitConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "junit",
		DisplayName:    "JUnit to HDF",
		FixtureDir:     "junit-to-hdf",
		MinimalFixture: "input/surefire-failing.xml",
		ErrPrefix:      "junit conversion failed",
		InvalidInput:   "not valid xml",
	})
}
