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

// TestLabelGatesInput: label set/remove/show reject a legacy v2, non-HDF, or
// fingerprint-valid-but-schema-invalid document at the boundary — instead of
// mutating (set/remove) or rendering (show) it. Mutating paths must not write.
func TestLabelGatesInput(t *testing.T) {
	cases := []struct {
		name, doc, wantErr string
	}{
		{"legacy v2", `{"platform":{"name":"x"},"version":"1.0.0","statistics":{},"profiles":[]}`, "hdf convert"},
		{"non-HDF", `{"hello":"world"}`, "not a recognized HDF document"},
		{"schema-invalid results", `{"baselines":[{}]}`, "schema"},
	}
	writeDoc := func(t *testing.T, doc string) (path string, before string) {
		t.Helper()
		path = filepath.Join(t.TempDir(), "in.json")
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))
		return path, doc
	}
	for _, tc := range cases {
		t.Run("set rejects "+tc.name, func(t *testing.T) {
			p, before := writeDoc(t, tc.doc)
			_, _, err := executeCommand("label", "set", p, "env=prod")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			after, readErr := os.ReadFile(p)
			require.NoError(t, readErr)
			assert.Equal(t, before, string(after), "a rejected label set must not modify the file")
		})
		t.Run("remove rejects "+tc.name, func(t *testing.T) {
			p, before := writeDoc(t, tc.doc)
			_, _, err := executeCommand("label", "remove", p, "env")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			after, readErr := os.ReadFile(p)
			require.NoError(t, readErr)
			assert.Equal(t, before, string(after), "a rejected label remove must not modify the file")
		})
		t.Run("show rejects "+tc.name, func(t *testing.T) {
			p, _ := writeDoc(t, tc.doc)
			_, _, err := executeCommand("label", "show", p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestLabel_AcceptsSystemDocument locks the decision that label operates on both
// results AND system documents (labels live on components[], which both carry —
// mirroring `hdf list`), not results alone.
func TestLabel_AcceptsSystemDocument(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sys.json")
	require.NoError(t, os.WriteFile(p, []byte(`{"name":"sys","components":[{"name":"h1","type":"host"}]}`), 0o600))

	_, _, err := executeCommand("label", "set", p, "env=prod")
	require.NoError(t, err)

	data, err := os.ReadFile(p)
	require.NoError(t, err)
	var doc struct {
		Components []struct {
			Labels map[string]string `json:"labels"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Len(t, doc.Components, 1)
	assert.Equal(t, "prod", doc.Components[0].Labels["env"])

	stdout, _, err := executeCommand("label", "show", p)
	require.NoError(t, err)
	assert.Contains(t, stdout, "env = prod")
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
