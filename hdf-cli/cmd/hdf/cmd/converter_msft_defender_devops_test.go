package cmd

import "testing"

func TestMsftDefenderDevopsConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "msft-defender-devops",
		DisplayName:    "Microsoft Defender for DevOps to HDF",
		FixtureDir:     "msft-defender-devops-to-hdf",
		MinimalFixture: "input/minimal.sarif",
		ErrPrefix:      "msft-defender-devops conversion failed",
	})
}

func TestMsftDefenderDevopsAlias(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "msdo",
		DisplayName:    "Microsoft Defender for DevOps to HDF",
		FixtureDir:     "msft-defender-devops-to-hdf",
		MinimalFixture: "input/minimal.sarif",
		ErrPrefix:      "msft-defender-devops conversion failed",
	})
}
