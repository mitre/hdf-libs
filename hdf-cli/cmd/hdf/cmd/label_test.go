package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createLabelTestFixture creates a temporary HDF file with targets for label tests.
func createLabelTestFixture(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	fixturePath := filepath.Join(tmpDir, "test-hdf.json")

	content := `{
  "baselines": [],
  "statistics": {"duration": 0.1},
  "components": [
    {"name": "test-system", "type": "host"},
    {"name": "web-server", "type": "host"}
  ]
}`
	require.NoError(t, os.WriteFile(fixturePath, []byte(content), 0o600))
	return fixturePath
}

func TestLabelShowCommand(t *testing.T) {
	t.Run("shows targets with no labels", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		stdout, _, err := executeCommand("label", "show", fixture)
		require.NoError(t, err)
		assert.Contains(t, stdout, "test-system")
		assert.Contains(t, stdout, "web-server")
		assert.Contains(t, stdout, "(no labels)")
	})

	t.Run("shows targets with labels", func(t *testing.T) {
		fixture := createLabelTestFixture(t)

		// First set a label
		_, _, err := executeCommand("label", "set", fixture, "env=prod")
		require.NoError(t, err)

		stdout, _, err := executeCommand("label", "show", fixture)
		require.NoError(t, err)
		assert.Contains(t, stdout, "env = prod")
	})

	t.Run("shows labels in JSON format", func(t *testing.T) {
		fixture := createLabelTestFixture(t)

		// Set a label first
		_, _, err := executeCommand("label", "set", fixture, "env=prod")
		require.NoError(t, err)

		stdout, _, err := executeCommand("label", "show", "--json", fixture)
		require.NoError(t, err)

		var infos []componentLabelInfo
		require.NoError(t, json.Unmarshal([]byte(stdout), &infos))
		require.Len(t, infos, 2)
		assert.Equal(t, "prod", infos[0].Labels["env"])
	})

	t.Run("nonexistent file returns error", func(t *testing.T) {
		_, _, err := executeCommand("label", "show", "/nonexistent/file.json")
		require.Error(t, err)
	})
}

func TestLabelSetCommand(t *testing.T) {
	t.Run("sets a single label", func(t *testing.T) {
		fixture := createLabelTestFixture(t)

		_, _, err := executeCommand("label", "set", fixture, "system=Portal")
		require.NoError(t, err)

		// Verify the label was applied
		data, err := os.ReadFile(fixture)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &doc))

		targets := doc["components"].([]interface{})
		for _, tRaw := range targets {
			target := tRaw.(map[string]interface{})
			labels := target["labels"].(map[string]interface{})
			assert.Equal(t, "Portal", labels["system"])
		}
	})

	t.Run("sets multiple labels", func(t *testing.T) {
		fixture := createLabelTestFixture(t)

		_, _, err := executeCommand("label", "set", fixture, "env=prod", "team=security")
		require.NoError(t, err)

		data, err := os.ReadFile(fixture)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &doc))

		targets := doc["components"].([]interface{})
		target := targets[0].(map[string]interface{})
		labels := target["labels"].(map[string]interface{})
		assert.Equal(t, "prod", labels["env"])
		assert.Equal(t, "security", labels["team"])
	})

	t.Run("writes to alternate output file", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "output.json")

		_, _, err := executeCommand("label", "set", fixture, "env=prod", "-o", outputPath)
		require.NoError(t, err)

		// Original should be unchanged
		originalData, err := os.ReadFile(fixture)
		require.NoError(t, err)
		var originalDoc map[string]interface{}
		require.NoError(t, json.Unmarshal(originalData, &originalDoc))
		targets := originalDoc["components"].([]interface{})
		target := targets[0].(map[string]interface{})
		_, hasLabels := target["labels"]
		assert.False(t, hasLabels, "original file should not have labels")

		// Output should have labels
		outputData, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		var outputDoc map[string]interface{}
		require.NoError(t, json.Unmarshal(outputData, &outputDoc))
		outTargets := outputDoc["components"].([]interface{})
		outTarget := outTargets[0].(map[string]interface{})
		outLabels := outTarget["labels"].(map[string]interface{})
		assert.Equal(t, "prod", outLabels["env"])
	})

	t.Run("invalid label format returns error", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "noequalssign")
		require.Error(t, err)
	})

	t.Run("no args returns error", func(t *testing.T) {
		_, _, err := executeCommand("label", "set")
		require.Error(t, err)
	})
}

func TestLabelRemoveCommand(t *testing.T) {
	t.Run("removes an existing label", func(t *testing.T) {
		fixture := createLabelTestFixture(t)

		// Set a label first
		_, _, err := executeCommand("label", "set", fixture, "env=prod", "team=security")
		require.NoError(t, err)

		// Remove one label
		_, _, err = executeCommand("label", "remove", fixture, "env")
		require.NoError(t, err)

		data, err := os.ReadFile(fixture)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &doc))

		targets := doc["components"].([]interface{})
		target := targets[0].(map[string]interface{})
		labels := target["labels"].(map[string]interface{})
		assert.NotContains(t, labels, "env")
		assert.Equal(t, "security", labels["team"])
	})

	t.Run("removes nonexistent key silently", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "remove", fixture, "nonexistent")
		require.NoError(t, err)
	})

	t.Run("writes to alternate output file", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "output.json")

		// Set a label first
		_, _, err := executeCommand("label", "set", fixture, "env=prod")
		require.NoError(t, err)

		// Remove to a different file
		_, _, err = executeCommand("label", "remove", fixture, "env", "-o", outputPath)
		require.NoError(t, err)

		// Original should still have the label
		originalData, err := os.ReadFile(fixture)
		require.NoError(t, err)
		var originalDoc map[string]interface{}
		require.NoError(t, json.Unmarshal(originalData, &originalDoc))
		targets := originalDoc["components"].([]interface{})
		target := targets[0].(map[string]interface{})
		labels := target["labels"].(map[string]interface{})
		assert.Equal(t, "prod", labels["env"])

		// Output should not have the label
		outputData, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		var outputDoc map[string]interface{}
		require.NoError(t, json.Unmarshal(outputData, &outputDoc))
		outTargets := outputDoc["components"].([]interface{})
		outTarget := outTargets[0].(map[string]interface{})
		outLabels := outTarget["labels"].(map[string]interface{})
		assert.NotContains(t, outLabels, "env")
	})

	t.Run("no args returns error", func(t *testing.T) {
		_, _, err := executeCommand("label", "remove")
		require.Error(t, err)
	})
}

func TestLabelSet_ComponentId(t *testing.T) {
	t.Run("stamps componentId on all components", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "--component-id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
		require.NoError(t, err)

		data, err := os.ReadFile(fixture)
		require.NoError(t, err)
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &doc))
		components := doc["components"].([]interface{})
		for _, cRaw := range components {
			comp := cRaw.(map[string]interface{})
			assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", comp["componentId"])
		}
	})

	t.Run("generate-component-id assigns unique UUIDs", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "--generate-component-id")
		require.NoError(t, err)

		data, err := os.ReadFile(fixture)
		require.NoError(t, err)
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &doc))
		components := doc["components"].([]interface{})
		ids := make(map[string]bool)
		for _, cRaw := range components {
			comp := cRaw.(map[string]interface{})
			id, ok := comp["componentId"].(string)
			require.True(t, ok, "componentId should be set")
			assert.Len(t, id, 36, "should be a UUID")
			assert.False(t, ids[id], "each component should get a unique ID")
			ids[id] = true
		}
	})
}
