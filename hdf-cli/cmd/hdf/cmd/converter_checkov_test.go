//nolint:dupl
package cmd

import "testing"

func TestCheckovConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "checkov",
		DisplayName:    "Checkov to HDF",
		FixtureDir:     "checkov-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "checkov conversion failed",
	})
}
