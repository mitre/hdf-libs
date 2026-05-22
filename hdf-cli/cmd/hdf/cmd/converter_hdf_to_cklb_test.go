package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToCKLBConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "cklb")
	require.NoError(t, err, "HDF-to-CKLB converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "HDF to CKLB", converter.Name())
}

func TestHDFToCKLBConverter_Convert(t *testing.T) {
	converter, err := GetConverter("hdf", "cklb")
	require.NoError(t, err, "Failed to get HDF-to-CKLB converter")

	input := []byte(`{
		"baselines": [{
			"name": "Test Baseline",
			"version": "1.0.0",
			"title": "Test",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "V-1",
				"title": "Test",
				"descriptions": [{ "label": "default", "data": "desc" }],
				"impact": 0.5,
				"tags": { "nist": ["SI-2 c"] },
				"sourceLocation": { "ref": "V-1", "line": 1 },
				"results": [{ "status": "failed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
			}]
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`)

	output, err := converter.Convert(input)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(output, &parsed), "output should be valid JSON")
	_, ok := parsed["stigs"]
	assert.True(t, ok, "CKLB output should contain a stigs array")
}

func TestHDFToCKLBConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "cklb")
	require.NoError(t, err, "Failed to get HDF-to-CKLB converter")

	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should error on invalid JSON")
}
