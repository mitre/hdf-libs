package cmd

import "testing"

func TestJfrogXrayConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "jfrog-xray",
		DisplayName:    "JFrog Xray to HDF",
		FixtureDir:     "jfrog-xray-to-hdf",
		MinimalFixture: "input/jfrog_xray_sample.json",
		ErrPrefix:      "jfrog-xray conversion failed",
	})
}

func TestJfrogXrayConverterAlias(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "xray",
		DisplayName:    "JFrog Xray to HDF",
		FixtureDir:     "jfrog-xray-to-hdf",
		MinimalFixture: "input/jfrog_xray_sample.json",
		ErrPrefix:      "jfrog-xray conversion failed",
	})
}
