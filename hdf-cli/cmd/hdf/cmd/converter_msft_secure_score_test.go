package cmd

import (
	"testing"
)

func TestMsftSecureScoreConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "msft-secure-score",
		DisplayName:    "Microsoft Secure Score to HDF",
		FixtureDir:     "msft-secure-score-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "msft-secure-score conversion failed",
	})
}
