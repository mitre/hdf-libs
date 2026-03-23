package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Minimal HDF results with two targets and two baselines.
const minimalResultsJSON = `{
  "baselines": [
    {
      "name": "RHEL9-STIG",
      "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"},
      "supports": [],
      "requirements": [],
      "groups": [],
      "depends": [],
      "inputs": []
    },
    {
      "name": "Container-STIG",
      "checksum": {"algorithm": "sha256", "value": "1111111111111111111111111111111111111111111111111111111111111111"},
      "supports": [],
      "requirements": [],
      "groups": [],
      "depends": [],
      "inputs": []
    }
  ],
  "targets": [
    {"name": "web-server-01", "type": "host"},
    {"name": "my-container", "type": "containerImage"}
  ],
  "statistics": {"duration": 120.5},
  "generator": {"name": "inspec", "version": "5.0"}
}`

func TestSystemCreate_Basic(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	// System name derived from first target
	assert.Equal(t, "web-server-01", sys["name"])

	// Components created from targets
	components, ok := sys["components"].([]interface{})
	require.True(t, ok)
	assert.Len(t, components, 2)

	// First component
	c0, ok := components[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "web-server-01", c0["name"])
	assert.Equal(t, "compute", c0["type"]) // host -> compute

	// Check baselineRefs are set from baselines
	refs0, ok := c0["baselineRefs"].([]interface{})
	require.True(t, ok)
	assert.Len(t, refs0, 2) // both baselines referenced

	// Second component
	c1, ok := components[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "my-container", c1["name"])
	assert.Equal(t, "compute", c1["type"]) // containerImage -> compute

	// Interconnections should be empty array
	interconnections, ok := sys["interconnections"].([]interface{})
	require.True(t, ok)
	assert.Empty(t, interconnections)

	// Generator metadata
	gen, ok := sys["generator"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "hdf-cli", gen["name"])
}

func TestSystemCreate_NameFlag(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "--name", "My Custom System", "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))
	assert.Equal(t, "My Custom System", sys["name"])
}

func TestSystemCreate_Stdout(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(minimalResultsJSON), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile})

	// Should succeed (output to stdout)
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestSystemCreate_MissingFromFlag(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create"})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestSystemCreate_MissingFile(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", "/nonexistent/results.json"})

	err := cmd.Execute()
	assert.Error(t, err)
}

func TestSystemCreate_InvalidJSON(t *testing.T) {
	resultsFile := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte("not json"), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestSystemCreate_NoTargets(t *testing.T) {
	noTargets := `{
		"baselines": [{"name": "B1", "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}, "supports": [], "requirements": [], "groups": [], "depends": [], "inputs": []}],
		"targets": [],
		"statistics": {"duration": 1},
		"generator": {"name": "test", "version": "1.0"}
	}`
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(noTargets), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no targets")
}

func TestSystemCreate_TargetLabelsAsSelector(t *testing.T) {
	withLabels := `{
		"baselines": [{"name": "B1", "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}, "supports": [], "requirements": [], "groups": [], "depends": [], "inputs": []}],
		"targets": [
			{"name": "labeled-host", "type": "host", "labels": {"env": "prod", "tier": "web"}}
		],
		"statistics": {"duration": 1},
		"generator": {"name": "test", "version": "1.0"}
	}`
	resultsFile := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(resultsFile, []byte(withLabels), 0o600))

	outFile := filepath.Join(t.TempDir(), "system.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var sys map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &sys))

	components, ok := sys["components"].([]interface{})
	require.True(t, ok)
	require.Len(t, components, 1)

	c0, ok := components[0].(map[string]interface{})
	require.True(t, ok)

	sel, ok := c0["targetSelector"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "prod", sel["env"])
	assert.Equal(t, "web", sel["tier"])
}

func TestSystemCreate_TypeMapping(t *testing.T) {
	// Test various target type -> component type mappings
	tests := []struct {
		targetType    string
		componentType string
	}{
		{"host", "compute"},
		{"containerImage", "compute"},
		{"containerInstance", "compute"},
		{"containerPlatform", "compute"},
		{"cloudAccount", "other"},
		{"cloudResource", "other"},
		{"application", "application"},
		{"database", "database"},
		{"network", "network"},
		{"repository", "storage"},
		{"artifact", "storage"},
	}

	for _, tt := range tests {
		t.Run(tt.targetType, func(t *testing.T) {
			resultsJSON := `{
				"baselines": [{"name": "B1", "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}, "supports": [], "requirements": [], "groups": [], "depends": [], "inputs": []}],
				"targets": [{"name": "target1", "type": "` + tt.targetType + `"}],
				"statistics": {"duration": 1},
				"generator": {"name": "test", "version": "1.0"}
			}`
			resultsFile := filepath.Join(t.TempDir(), "results.json")
			require.NoError(t, os.WriteFile(resultsFile, []byte(resultsJSON), 0o600))

			outFile := filepath.Join(t.TempDir(), "system.json")
			cmd := NewRootCmd()
			cmd.SetArgs([]string{"system", "create", "--from", resultsFile, "-o", outFile})

			err := cmd.Execute()
			require.NoError(t, err)

			data, err := os.ReadFile(outFile)
			require.NoError(t, err)

			var sys map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &sys))

			components := sys["components"].([]interface{})
			c0 := components[0].(map[string]interface{})
			assert.Equal(t, tt.componentType, c0["type"], "target type %s should map to component type %s", tt.targetType, tt.componentType)
		})
	}
}
