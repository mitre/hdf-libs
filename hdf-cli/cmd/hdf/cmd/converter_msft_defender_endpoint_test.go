package cmd

import "testing"

func TestMsftDefenderEndpointConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "msft-defender-endpoint",
		DisplayName:    "Microsoft Defender for Endpoint to HDF",
		FixtureDir:     "msft-defender-endpoint-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "msft-defender-endpoint conversion failed",
	})
}

func TestMsftDefenderEndpointAlias(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "defender-endpoint",
		DisplayName:    "Microsoft Defender for Endpoint to HDF",
		FixtureDir:     "msft-defender-endpoint-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "msft-defender-endpoint conversion failed",
	})
}
