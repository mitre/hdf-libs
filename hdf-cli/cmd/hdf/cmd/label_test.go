package cmd

import (
	"encoding/json"
	"errors"
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

	t.Run("non-UUID is rejected and the file is left untouched", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		before, err := os.ReadFile(fixture)
		require.NoError(t, err)

		_, _, err = executeCommand("label", "set", fixture, "env=prod", "--component-id", "CI0012345")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--component-id")
		assert.Contains(t, err.Error(), `"CI0012345"`)

		after, err := os.ReadFile(fixture)
		require.NoError(t, err)
		assert.Equal(t, string(before), string(after), "a rejected id must not write, labels included")
	})

	t.Run("non-UUID with --output creates no file", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		out := filepath.Join(t.TempDir(), "out.json")

		_, _, err := executeCommand("label", "set", fixture, "--component-id", "CI0012345", "-o", out)
		require.Error(t, err)
		assert.NoFileExists(t, out)
	})

	t.Run("an accepted id leaves a document that still validates", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "--component-id", "3F2504E0-4F89-11D3-9A0C-0305E82C3301")
		require.NoError(t, err)

		data, err := os.ReadFile(fixture)
		require.NoError(t, err)
		require.NoError(t, validateHDFDocument(data))
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

func readComponents(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	raw, _ := doc["components"].([]interface{})
	comps := make([]map[string]interface{}, len(raw))
	for i, c := range raw {
		comps[i] = c.(map[string]interface{})
	}
	return comps
}

func TestLabelSet_ExternalID(t *testing.T) {
	t.Run("writes each scheme on every component and the result validates", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "--external-id", "cmdb=CI0012345", "--external-id", "emass=1234")
		require.NoError(t, err)

		for _, comp := range readComponents(t, fixture) {
			assert.Equal(t, map[string]interface{}{"cmdb": "CI0012345", "emass": "1234"}, comp["externalIds"])
			assert.NotContains(t, comp, "labels", "an external id is not a label")
		}
		data, err := os.ReadFile(fixture)
		require.NoError(t, err)
		require.NoError(t, validateHDFDocument(data))
	})

	t.Run("merges: a named scheme is overwritten, others are kept", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "--external-id", "cmdb=OLD", "--external-id", "aws=i-0abc")
		require.NoError(t, err)
		_, _, err = executeCommand("label", "set", fixture, "--external-id", "cmdb=NEW")
		require.NoError(t, err)

		assert.Equal(t, map[string]interface{}{"cmdb": "NEW", "aws": "i-0abc"}, readComponents(t, fixture)[0]["externalIds"])
	})

	t.Run("a value with commas and equals signs is carried whole", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "--external-id", "azure=/subscriptions/a=b,c/vm")
		require.NoError(t, err)
		assert.Equal(t, "/subscriptions/a=b,c/vm", readComponents(t, fixture)[0]["externalIds"].(map[string]interface{})["azure"])
	})

	t.Run("combines with labels and --output", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		out := filepath.Join(t.TempDir(), "labeled.json")
		_, _, err := executeCommand("label", "set", fixture, "env=prod", "--external-id", "cmdb=CI0012345", "-o", out)
		require.NoError(t, err)

		comp := readComponents(t, out)[0]
		assert.Equal(t, "prod", comp["labels"].(map[string]interface{})["env"])
		assert.Equal(t, "CI0012345", comp["externalIds"].(map[string]interface{})["cmdb"])
	})

	t.Run("--component-name limits the write to that component", func(t *testing.T) {
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "--external-id", "cmdb=CI-WEB", "--component-name", "web-server")
		require.NoError(t, err)

		comps := readComponents(t, fixture)
		assert.NotContains(t, comps[0], "externalIds")
		assert.Equal(t, map[string]interface{}{"cmdb": "CI-WEB"}, comps[1]["externalIds"])
	})

	t.Run("works on a system document", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "system.json")
		require.NoError(t, os.WriteFile(path, []byte(`{
  "name": "Portal",
  "components": [{"name": "web", "type": "host", "componentId": "3f2504e0-4f89-11d3-9a0c-0305e82c3301"}]
}`), 0o600))
		before, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, validateHDFDocument(before), "the fixture must be a valid system document")

		_, _, err = executeCommand("label", "set", path, "--external-id", "emass=1234")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"emass": "1234"}, readComponents(t, path)[0]["externalIds"])
	})
}

func TestLabelSet_ExternalID_RejectsBeforeWriting(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no equals", []string{"--external-id", "cmdb"}, "scheme=value"},
		{"empty scheme", []string{"--external-id", "=CI0012345"}, "scheme must not be empty"},
		{"empty flag value", []string{"--external-id", ""}, "scheme=value"},
		{"empty value", []string{"--external-id", "cmdb="}, "value must not be empty"},
		{"duplicate scheme", []string{"--external-id", "cmdb=A", "--external-id", "cmdb=B"}, "more than once"},
		{"bad external id alongside a good label", []string{"env=prod", "--external-id", "cmdb="}, "value must not be empty"},
		{"unknown component", []string{"--external-id", "cmdb=A", "--component-name", "cache"}, `"cache"`},
		{"component name without an external id", []string{"env=prod", "--component-name", "web-server"}, "--component-name"},
		{"component name with labels", []string{"env=prod", "--external-id", "cmdb=A", "--component-name", "web-server"}, "--component-name"},
		{"component name with component id", []string{"--external-id", "cmdb=A", "--component-name", "web-server", "--generate-component-id"}, "--component-name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := createLabelTestFixture(t)
			before, err := os.ReadFile(fixture)
			require.NoError(t, err)
			out := filepath.Join(t.TempDir(), "out.json")

			_, _, err = executeCommand(append([]string{"label", "set", fixture, "-o", out}, tc.args...)...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.NoFileExists(t, out)

			_, _, err = executeCommand(append([]string{"label", "set", fixture}, tc.args...)...)
			require.Error(t, err)
			after, readErr := os.ReadFile(fixture)
			require.NoError(t, readErr)
			assert.Equal(t, string(before), string(after), "a rejected invocation writes nothing")
		})
	}

	t.Run("a document with no components fails instead of reporting success", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.json")
		doc := `{"baselines": [], "statistics": {"duration": 0.1}, "components": []}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		_, _, err := executeCommand("label", "set", path, "env=prod", "--external-id", "cmdb=CI0012345")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no components")
		after, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.Equal(t, doc, string(after))
	})
}

func TestLabelRemove_ExternalID(t *testing.T) {
	seed := func(t *testing.T) string {
		t.Helper()
		fixture := createLabelTestFixture(t)
		_, _, err := executeCommand("label", "set", fixture, "env=prod", "--external-id", "cmdb=CI0012345", "--external-id", "aws=i-0abc")
		require.NoError(t, err)
		return fixture
	}

	t.Run("removes one scheme with no label keys given", func(t *testing.T) {
		fixture := seed(t)
		_, _, err := executeCommand("label", "remove", fixture, "--external-id", "cmdb")
		require.NoError(t, err)

		comp := readComponents(t, fixture)[0]
		assert.Equal(t, map[string]interface{}{"aws": "i-0abc"}, comp["externalIds"])
		assert.Equal(t, "prod", comp["labels"].(map[string]interface{})["env"], "labels are untouched")
	})

	t.Run("removes labels and schemes together, dropping an emptied map", func(t *testing.T) {
		fixture := seed(t)
		_, _, err := executeCommand("label", "remove", fixture, "env", "--external-id", "cmdb", "--external-id", "aws")
		require.NoError(t, err)

		comp := readComponents(t, fixture)[0]
		assert.NotContains(t, comp, "externalIds")
		assert.NotContains(t, comp["labels"], "env")
		data, err := os.ReadFile(fixture)
		require.NoError(t, err)
		require.NoError(t, validateHDFDocument(data))
	})

	t.Run("--component-name limits the removal", func(t *testing.T) {
		fixture := seed(t)
		_, _, err := executeCommand("label", "remove", fixture, "--external-id", "cmdb", "--component-name", "web-server")
		require.NoError(t, err)

		comps := readComponents(t, fixture)
		assert.Contains(t, comps[0]["externalIds"], "cmdb")
		assert.NotContains(t, comps[1]["externalIds"], "cmdb")
	})

	for name, tc := range map[string]struct {
		args    []string
		wantErr string
	}{
		"nothing to remove":               {nil, "nothing to remove"},
		"empty scheme":                    {[]string{"--external-id", ""}, "scheme must not be empty"},
		"unknown component":               {[]string{"--external-id", "cmdb", "--component-name", "cache"}, `"cache"`},
		"component name without a scheme": {[]string{"env", "--component-name", "web-server"}, "--component-name"},
		"component name with a label key": {[]string{"env", "--external-id", "cmdb", "--component-name", "web-server"}, "--component-name"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := seed(t)
			before, err := os.ReadFile(fixture)
			require.NoError(t, err)

			_, _, err = executeCommand(append([]string{"label", "remove", fixture}, tc.args...)...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			after, readErr := os.ReadFile(fixture)
			require.NoError(t, readErr)
			assert.Equal(t, string(before), string(after))
		})
	}
}

func TestLabelShow_ExternalIDs(t *testing.T) {
	fixture := createLabelTestFixture(t)
	_, _, err := executeCommand("label", "set", fixture, "--external-id", "cmdb=CI-WEB", "--external-id", "aws=i-0abc", "--component-name", "web-server")
	require.NoError(t, err)

	t.Run("text lists external ids, sorted, under the component that has them", func(t *testing.T) {
		stdout, _, err := executeCommand("label", "show", fixture)
		require.NoError(t, err)
		assert.Equal(t, `Component: test-system [host]
  (no labels)

Component: web-server [host]
  (no labels)
  External IDs:
    aws = i-0abc
    cmdb = CI-WEB
`, stdout)
	})

	t.Run("json carries externalIds for every component", func(t *testing.T) {
		stdout, _, err := executeCommand("label", "show", "--json", fixture)
		require.NoError(t, err)

		var raw []map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &raw))
		require.Len(t, raw, 2)
		assert.Equal(t, map[string]interface{}{}, raw[0]["externalIds"])
		assert.Equal(t, map[string]interface{}{"cmdb": "CI-WEB", "aws": "i-0abc"}, raw[1]["externalIds"])
		assert.Equal(t, map[string]interface{}{}, raw[1]["labels"], "the existing labels key is unchanged")
	})
}

// --component-name promises one component (help text, CHANGELOG, label-keys
// reference), so a name two components share is rejected rather than written to
// both.
func TestLabelExternalID_AmbiguousComponentNameRejectedBeforeWriting(t *testing.T) {
	duplicateNames := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "dup-names.json")
		require.NoError(t, os.WriteFile(path, []byte(`{
  "baselines": [],
  "statistics": {"duration": 0.1},
  "components": [
    {"name": "web", "type": "host", "externalIds": {"cmdb": "CI0012345"}},
    {"name": "web", "type": "containerImage"}
  ]
}`), 0o600))
		return path
	}

	cases := []struct {
		name string
		args []string
	}{
		{"set", []string{"label", "set", "", "--external-id", "cmdb=NEW", "--component-name", "web"}},
		{"remove", []string{"label", "remove", "", "--external-id", "cmdb", "--component-name", "web"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := duplicateNames(t)
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, validateHDFDocument(before), "the fixture must be a valid results document")

			args := append([]string(nil), tc.args...)
			args[2] = path
			_, _, err = executeCommand(args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `component name "web" matches 2 components`)

			var ec ExitCoder
			assert.False(t, errors.As(err, &ec), "a plain error leaves the CLI exiting 1")

			after, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, before, after, "a rejected invocation leaves the file byte-identical")
		})
	}
}

// writeLabelOutput is the label commands' only write path, and every sibling
// mutator validates its output before the write.
func TestWriteLabelOutput_RefusesAnInvalidDocument(t *testing.T) {
	target := filepath.Join(t.TempDir(), "out.json")
	invalid := []byte(`{"baselines":[{}]}`)
	require.Error(t, validateHDFDocument(invalid), "the document must be schema-invalid for this test to mean anything")

	err := writeLabelOutput(invalid, target, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed validation before write")
	assert.NoFileExists(t, target, "an invalid document must not reach the disk")
}
