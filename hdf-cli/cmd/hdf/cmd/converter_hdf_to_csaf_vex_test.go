package cmd

import (
	"encoding/json"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToCSAFVEXConverter_Registered(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "csaf-vex")
	require.NoError(t, err)
	assert.Equal(t, "HDF Amendments to CSAF VEX", converter.Name())
}

func TestHDFToCSAFVEXConverter_ProducesCSAFVexEnvelope(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "csaf-vex")
	require.NoError(t, err)

	input := fixtures.Amendments.MultiCVE

	output, err := converter.Convert(input)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(output, &doc))
	dm, ok := doc["document"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "csaf_vex", dm["category"])
}

func TestHDFToCSAFVEXConverter_RejectsInvalidInput(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "csaf-vex")
	require.NoError(t, err)

	_, err = converter.Convert([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hdf-to-csaf-vex conversion failed")
}
