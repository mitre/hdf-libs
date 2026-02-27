package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSarifConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "sarif",
		DisplayName:    "SARIF to HDF",
		FixtureDir:     "sarif-to-hdf",
		MinimalFixture: "input/sarif_input.sarif",
		ErrPrefix:      "sarif conversion failed",
	})
}

func TestSarifConverter_Convert_InvalidStructure(t *testing.T) {
	converter, err := GetConverter("sarif", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(`{"not": "sarif"}`))
	assert.Error(t, err, "Should fail on invalid SARIF structure")
	assert.Nil(t, output)
}
