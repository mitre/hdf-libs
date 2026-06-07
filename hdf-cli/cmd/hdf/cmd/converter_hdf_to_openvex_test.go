package cmd

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToOpenVEXConverter_Registered(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "openvex")
	require.NoError(t, err)
	assert.Equal(t, "HDF Amendments to OpenVEX", converter.Name())
}

func TestHDFToOpenVEXConverter_ProducesOpenVexEnvelope(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "openvex")
	require.NoError(t, err)

	path := converterFixturePath(t, "hdf-to-openvex", "input/spring-boot-log4j-amendments.json")
	input, err := os.ReadFile(path)
	require.NoError(t, err)

	output, err := converter.Convert(input)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(output, &doc))
	assert.Contains(t, doc["@context"], "openvex.dev")
	stmts, ok := doc["statements"].([]any)
	require.True(t, ok)
	require.Len(t, stmts, 1)
}

func TestHDFToOpenVEXConverter_RejectsInvalidInput(t *testing.T) {
	converter, err := GetConverter("hdf-amendments", "openvex")
	require.NoError(t, err)

	_, err = converter.Convert([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hdf-to-openvex conversion failed")
}
