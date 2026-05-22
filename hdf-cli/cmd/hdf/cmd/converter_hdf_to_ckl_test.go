package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToCKLConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "ckl")
	require.NoError(t, err, "HDF-to-CKL converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "HDF to CKL", converter.Name())
}

func TestHDFToCKLConverter_Convert(t *testing.T) {
	input := []byte(`{
		"baselines": [{
			"name": "Synthetic Baseline",
			"version": "1.0.0",
			"title": "Synthetic",
			"maintainer": "Test",
			"supports": [],
			"inputs": [],
			"groups": [],
			"checksum": { "algorithm": "sha256", "value": "abc" },
			"requirements": [{
				"id": "GEN-001",
				"title": "Generic Requirement",
				"descriptions": [{ "label": "default", "data": "desc" }],
				"impact": 0.5,
				"tags": { "nist": ["SI-2 c"] },
				"sourceLocation": { "ref": "GEN-001", "line": 1 },
				"results": [{ "status": "failed", "codeDesc": "Test", "startTime": "2026-01-29T18:00:00.000Z" }]
			}]
		}],
		"components": [],
		"statistics": { "duration": 0 }
	}`)

	converter, err := GetConverter("hdf", "ckl")
	require.NoError(t, err, "Failed to get HDF-to-CKL converter")

	output, err := converter.Convert(input)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")
	assert.Contains(t, string(output), "<CHECKLIST>")
}

func TestHDFToCKLConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "ckl")
	require.NoError(t, err, "Failed to get HDF-to-CKL converter")

	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should error on invalid JSON")
}
