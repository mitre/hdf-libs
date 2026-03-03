package cmd

import (
	"testing"
)

func TestNeuVectorConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "neuvector",
		DisplayName:    "NeuVector to HDF",
		FixtureDir:     "neuvector-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "neuvector conversion failed",
	})
}
