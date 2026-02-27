package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrypeConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "grype",
		DisplayName:    "Grype to HDF",
		FixtureDir:     "grype-to-hdf",
		MinimalFixture: "input/amazon.json",
		ErrPrefix:      "grype conversion failed",
	})
}

func TestGrypeConverter_Convert_InvalidStructure(t *testing.T) {
	converter, err := GetConverter("grype", "hdf")
	require.NoError(t, err)

	// The converter is lenient and will accept a minimal structure, using defaults for missing fields.
	minimalGrype := []byte(`{"descriptor": {"name": "grype"}, "source": {"target": {"userInput": "test"}}, "matches": []}`)
	output, err := converter.Convert(minimalGrype)
	assert.NoError(t, err, "Should handle minimal structure gracefully")
	assert.NotNil(t, output)
	assert.Contains(t, string(output), "\"baselines\"")
}
