package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToOCSFConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "ocsf")
	require.NoError(t, err, "HDF-to-OCSF converter should be registered")
	require.NotNil(t, converter)
	assert.Equal(t, "HDF Results to OCSF Findings", converter.Name())
}

func TestHDFToOCSFConverter_Convert_Findings(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-ocsf", "input/cve.json"))
	require.NoError(t, err)

	converter, err := GetConverter("hdf", "ocsf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	require.NotEmpty(t, output)
	require.Equal(t, byte('\n'), output[len(output)-1], "NDJSON must end with a trailing newline")

	lines := bytes.Split(bytes.TrimRight(output, "\n"), []byte("\n"))
	require.Len(t, lines, 3)
	for _, line := range lines {
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(line, &m), "each line must be a standalone OCSF finding")
		assert.Equal(t, float64(2002), m["class_uid"], "cve findings are Vulnerability Findings")
		assert.NotNil(t, m["vulnerabilities"])
	}
}

func TestHDFToOCSFConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "ocsf")
	require.NoError(t, err)
	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
}

func TestHDFToOCSFConverter_Convert_EmptyBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "ocsf")
	require.NoError(t, err)
	output, err := converter.Convert([]byte(`{"baselines": []}`))
	require.NoError(t, err, "empty baselines yields no events, not an error")
	assert.Empty(t, output)
}
