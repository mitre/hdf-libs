package cmd

import (
	"encoding/json"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToSplunkConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "splunk")
	require.NoError(t, err, "HDF-to-Splunk converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "HDF to Splunk records", converter.Name())
}

func TestHDFToSplunkConverter_Convert_Minimal(t *testing.T) {
	inputData := fixtures.Results.Minimal
	require.NotEmpty(t, inputData)

	converter, err := GetConverter("hdf", "splunk")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	var doc struct {
		Reports  []json.RawMessage `json:"reports"`
		Profiles []json.RawMessage `json:"profiles"`
		Controls []json.RawMessage `json:"controls"`
	}
	require.NoError(t, json.Unmarshal(output, &doc), "output must be valid JSON with reports/profiles/controls keys")
	assert.Len(t, doc.Reports, 1)
	assert.NotEmpty(t, doc.Profiles)
	assert.NotEmpty(t, doc.Controls)
}

func TestHDFToSplunkConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "splunk")
	require.NoError(t, err)

	_, err = converter.Convert([]byte("not valid"))
	assert.Error(t, err)
}

func TestHDFToSplunkConverter_Convert_NoBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "splunk")
	require.NoError(t, err)

	_, err = converter.Convert([]byte(`{"baselines": []}`))
	assert.Error(t, err)
}
