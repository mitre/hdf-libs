package cmd

import "testing"

func TestNexusIQConverter(t *testing.T) {
	for _, source := range []string{"nexusiq", "sonatype", "lifecycle"} {
		t.Run(source, func(t *testing.T) {
			runStandardConverterTests(t, converterTestCase{
				Source:         source,
				DisplayName:    "Nexus IQ to HDF",
				FixtureDir:     "nexusiq-to-hdf",
				MinimalFixture: "input/policy-evaluation.json",
				ErrPrefix:      "nexusiq conversion failed",
			})
		})
	}
}
