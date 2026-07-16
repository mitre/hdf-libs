package cmd

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToASFFConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "asff")
	require.NoError(t, err, "HDF-to-ASFF converter should be registered")
	require.NotNil(t, converter)
	assert.Equal(t, "HDF Results to ASFF Findings", converter.Name())
}

func TestHDFToASFFConverter_Convert_Findings(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-asff", "input/cve.json"))
	require.NoError(t, err)

	converter, err := GetConverter("hdf", "asff")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	var env struct {
		Findings []map[string]interface{} `json:"Findings"`
	}
	require.NoError(t, json.Unmarshal(output, &env), "output must be an ASFF Findings envelope")
	require.NotEmpty(t, env.Findings)
	for _, f := range env.Findings {
		assert.Equal(t, "2018-10-08", f["SchemaVersion"])
		assert.Equal(t, []interface{}{"Software and Configuration Checks/Vulnerabilities/CVE"}, f["Types"])
	}
}

func TestHDFToASFFConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "asff")
	require.NoError(t, err)
	_, err = converter.Convert([]byte("not valid json"))
	assert.Error(t, err)
}

func TestHDFToASFFConverter_Convert_EmptyBaselines(t *testing.T) {
	converter, err := GetConverter("hdf", "asff")
	require.NoError(t, err)
	output, err := converter.Convert([]byte(`{"baselines": []}`))
	require.NoError(t, err, "empty baselines yields an empty Findings envelope, not an error")
	var env struct {
		Findings []map[string]interface{} `json:"Findings"`
	}
	require.NoError(t, json.Unmarshal(output, &env))
	assert.Empty(t, env.Findings)
}
