package cmd

import "testing"

func TestTwistlockConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "twistlock",
		DisplayName:    "Twistlock to HDF",
		FixtureDir:     "twistlock-to-hdf",
		MinimalFixture: "input/twistlock-twistcli-coderepo-scan-sample.json",
		ErrPrefix:      "twistlock conversion failed",
	})
}
