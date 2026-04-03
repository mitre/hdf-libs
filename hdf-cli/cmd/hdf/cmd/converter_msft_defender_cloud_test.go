package cmd

import "testing"

func TestMsftDefenderCloudConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "msft-defender-cloud",
		DisplayName:    "Microsoft Defender for Cloud to HDF",
		FixtureDir:     "msft-defender-cloud-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "msft-defender-cloud conversion failed",
	})
}

func TestMsftDefenderCloudAlias(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "defender-cloud",
		DisplayName:    "Microsoft Defender for Cloud to HDF",
		FixtureDir:     "msft-defender-cloud-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "msft-defender-cloud conversion failed",
	})
}
