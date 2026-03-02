package cmd

import (
	"testing"
)

func TestDbprotectConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "dbprotect",
		DisplayName:    "DBProtect to HDF",
		FixtureDir:     "dbprotect-to-hdf",
		MinimalFixture: "input/sample-check-results.xml",
		ErrPrefix:      "dbprotect conversion failed",
		InvalidInput:   "not valid xml",
	})
}
