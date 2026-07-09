package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToSplunkConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "splunk")
	require.NoError(t, err, "HDF-to-Splunk converter should be registered")
	require.NotNil(t, converter)
	assert.Equal(t, "HDF Results to Splunk (CIM/HEC)", converter.Name())
}

func TestHDFToSplunkConverter_Convert_HECNDJSON(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-splunk", "input/cve.json"))
	require.NoError(t, err)

	converter, err := GetConverter("hdf", "splunk")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	require.NotEmpty(t, output)
	require.Equal(t, byte('\n'), output[len(output)-1], "NDJSON must end with a trailing newline")

	lines := bytes.Split(bytes.TrimRight(output, "\n"), []byte("\n"))
	require.Len(t, lines, 3)
	for _, line := range lines {
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(line, &m), "each line must be a standalone HEC event")
		assert.Equal(t, "hdf:results", m["sourcetype"])
		event, _ := m["event"].(map[string]interface{})
		require.NotNil(t, event)
		assert.Contains(t, event["cve"], "CVE-")
	}
}

func TestHDFToSplunkConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "splunk")
	require.NoError(t, err)
	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
}

func TestHDFToSplunkConverter_Convert_EmptyBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "splunk")
	require.NoError(t, err)
	output, err := converter.Convert([]byte(`{"baselines": []}`))
	require.NoError(t, err, "empty baselines yields no events, not an error")
	assert.Empty(t, output)
}
