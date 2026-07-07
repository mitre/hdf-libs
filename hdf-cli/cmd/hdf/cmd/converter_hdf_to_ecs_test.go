package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToECSConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "ecs")
	require.NoError(t, err, "HDF-to-ECS converter should be registered")
	require.NotNil(t, converter)
	assert.Equal(t, "HDF Results to ECS", converter.Name())
}

func TestHDFToECSConverter_Convert_NDJSON(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-ecs", "input/cve.json"))
	require.NoError(t, err)

	converter, err := GetConverter("hdf", "ecs")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	require.NotEmpty(t, output)
	require.Equal(t, byte('\n'), output[len(output)-1], "NDJSON must end with a trailing newline")

	// Every line is a standalone ECS event object.
	lines := bytes.Split(bytes.TrimRight(output, "\n"), []byte("\n"))
	require.Len(t, lines, 3)
	for _, line := range lines {
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(line, &m), "each line must be standalone JSON")
		ecs, _ := m["ecs"].(map[string]interface{})
		assert.Equal(t, "9.4.0", ecs["version"])
		event, _ := m["event"].(map[string]interface{})
		assert.Contains(t, event["category"], "vulnerability")
	}
}

func TestHDFToECSConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "ecs")
	require.NoError(t, err)
	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
}

func TestHDFToECSConverter_Convert_EmptyBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "ecs")
	require.NoError(t, err)
	output, err := converter.Convert([]byte(`{"baselines": []}`))
	require.NoError(t, err, "empty baselines yields no events, not an error")
	assert.Empty(t, output)
}
