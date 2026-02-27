package cmd

import "testing"

func TestZapConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "zap",
		DisplayName:    "OWASP ZAP to HDF",
		FixtureDir:     "zap-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "zap conversion failed",
	})
}
