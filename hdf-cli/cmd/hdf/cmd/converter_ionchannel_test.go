//nolint:dupl
package cmd

import "testing"

func TestIonChannelConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "ionchannel",
		DisplayName:    "Ion Channel to HDF",
		FixtureDir:     "ionchannel-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "ionchannel conversion failed",
	})
}
