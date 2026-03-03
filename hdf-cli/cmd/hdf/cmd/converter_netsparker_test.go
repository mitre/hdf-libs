package cmd

import "testing"

func TestNetsparkerConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "netsparker",
		DisplayName:    "Netsparker/Invicti to HDF",
		FixtureDir:     "netsparker-to-hdf",
		MinimalFixture: "input/sample-netsparker-invicti.xml",
		ErrPrefix:      "netsparker conversion failed",
		InvalidInput:   "not valid xml",
	})
}

func TestInvictiConverterAlias(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "invicti",
		DisplayName:    "Netsparker/Invicti to HDF",
		FixtureDir:     "netsparker-to-hdf",
		MinimalFixture: "input/sample-netsparker-invicti.xml",
		ErrPrefix:      "netsparker conversion failed",
		InvalidInput:   "not valid xml",
	})
}
