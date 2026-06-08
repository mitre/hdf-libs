package cmd

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToCycloneDXVEXConverter_Registered(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "cyclonedx-vex")
	require.NoError(t, err)
	assert.Equal(t, "HDF Amendments to CycloneDX VEX", converter.Name())
}

func TestHDFToCycloneDXVEXConverter_ProducesCycloneDXEnvelope(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "cyclonedx-vex")
	require.NoError(t, err)

	path := converterFixturePath(t, "hdf-to-cyclonedx-vex", "input/case1-not_affected-amendments.json")
	input, err := os.ReadFile(path)
	require.NoError(t, err)

	output, err := converter.Convert(input)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(output, &doc))
	assert.Equal(t, "CycloneDX", doc["bomFormat"])
	vulns, ok := doc["vulnerabilities"].([]any)
	require.True(t, ok)
	require.Len(t, vulns, 1)
}

func TestHDFToCycloneDXVEXConverter_RejectsInvalidInput(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "cyclonedx-vex")
	require.NoError(t, err)

	_, err = converter.Convert([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hdf-to-cyclonedx-vex conversion failed")
}
