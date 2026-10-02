package hdfdoc

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	noTargetsJSON    = `{"baselines": []}`
	singleTargetJSON = `{"components": [{"name": "h1", "type": "host"}]}`
)

func TestApplyLabels(t *testing.T) {
	t.Run("apply labels to targets with no existing labels", func(t *testing.T) {
		input := `{
  "baselines": [],
  "components": [
    {"name": "host1", "type": "host"},
    {"name": "host2", "type": "host"}
  ]
}`
		labels := map[string]string{"env": "prod", "team": "security"}
		result, err := ApplyLabels([]byte(input), labels)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &doc))

		targets := doc["components"].([]interface{})
		for _, tRaw := range targets {
			target := tRaw.(map[string]interface{})
			targetLabels := target["labels"].(map[string]interface{})
			assert.Equal(t, "prod", targetLabels["env"])
			assert.Equal(t, "security", targetLabels["team"])
		}
	})

	t.Run("merge with existing labels", func(t *testing.T) {
		input := `{
  "components": [
    {"name": "host1", "type": "host", "labels": {"existing": "value"}}
  ]
}`
		labels := map[string]string{"env": "prod"}
		result, err := ApplyLabels([]byte(input), labels)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &doc))

		targets := doc["components"].([]interface{})
		target := targets[0].(map[string]interface{})
		targetLabels := target["labels"].(map[string]interface{})
		assert.Equal(t, "value", targetLabels["existing"])
		assert.Equal(t, "prod", targetLabels["env"])
	})

	t.Run("overwrite existing label key", func(t *testing.T) {
		input := `{
  "components": [
    {"name": "host1", "type": "host", "labels": {"env": "dev"}}
  ]
}`
		labels := map[string]string{"env": "prod"}
		result, err := ApplyLabels([]byte(input), labels)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &doc))

		targets := doc["components"].([]interface{})
		target := targets[0].(map[string]interface{})
		targetLabels := target["labels"].(map[string]interface{})
		assert.Equal(t, "prod", targetLabels["env"])
	})

	t.Run("no targets in document", func(t *testing.T) {
		input := noTargetsJSON
		labels := map[string]string{"env": "prod"}
		result, err := ApplyLabels([]byte(input), labels)
		require.NoError(t, err)
		// Should return unchanged
		assert.JSONEq(t, input, string(result))
	})

	t.Run("empty labels map is no-op", func(t *testing.T) {
		input := singleTargetJSON
		result, err := ApplyLabels([]byte(input), map[string]string{})
		require.NoError(t, err)
		assert.Equal(t, input, string(result))
	})

	t.Run("invalid JSON input", func(t *testing.T) {
		_, err := ApplyLabels([]byte("not json"), map[string]string{"k": "v"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JSON")
	})

	t.Run("targets is not an array", func(t *testing.T) {
		input := `{"components": "not-an-array"}`
		_, err := ApplyLabels([]byte(input), map[string]string{"k": "v"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not an array")
	})
}

const testComponentID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

func TestApplyComponentID_Fixed(t *testing.T) {
	out, err := ApplyComponentID([]byte(`{"components":[{"name":"h1"},{"name":"h2"}]}`), testComponentID, false)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	for _, c := range doc["components"].([]any) {
		assert.Equal(t, testComponentID, c.(map[string]any)["componentId"])
	}
}

func TestApplyComponentID_RejectsNonUUID(t *testing.T) {
	for _, id := range []string{"CI0012345", "fixed-123", " " + testComponentID, "aaaaaaaabbbb4ccc8dddeeeeeeeeeeee"} {
		t.Run(id, func(t *testing.T) {
			out, err := ApplyComponentID([]byte(`{"components":[{"name":"h1"}]}`), id, false)
			require.Error(t, err)
			assert.Nil(t, out, "a rejected id must hand back no document")
			assert.Contains(t, err.Error(), fmt.Sprintf("%q", id), "the error names the offending value")
			assert.Contains(t, err.Error(), "UUID")
		})
	}
}

// A bad id is a bad argument whether or not the document has anything to stamp.
func TestApplyComponentID_RejectsNonUUIDWithoutComponents(t *testing.T) {
	_, err := ApplyComponentID([]byte(`{"baselines":[]}`), "CI0012345", false)
	require.Error(t, err)
}

func TestValidateComponentID(t *testing.T) {
	require.NoError(t, ValidateComponentID(testComponentID))
	require.NoError(t, ValidateComponentID("3F2504E0-4F89-11D3-9A0C-0305E82C3301"), "RFC 4122 input is case-insensitive")
	require.Error(t, ValidateComponentID("CI0012345"))
	require.Error(t, ValidateComponentID(""))
}

func TestApplyComponentID_Generate(t *testing.T) {
	out, err := ApplyComponentID([]byte(`{"components":[{"name":"h1"},{"name":"h2"}]}`), "", true)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	comps := doc["components"].([]any)
	id0 := comps[0].(map[string]any)["componentId"].(string)
	id1 := comps[1].(map[string]any)["componentId"].(string)
	require.NoError(t, ValidateComponentID(id0))
	assert.NotEqual(t, id0, id1, "generate must mint a distinct UUID per component")
}

func TestApplyComponentID_NoComponents(t *testing.T) {
	in := []byte(`{"baselines":[]}`)
	out, err := ApplyComponentID(in, testComponentID, false)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestApplyComponentID_NothingRequested(t *testing.T) {
	out, err := ApplyComponentID([]byte(`{"components":[{"name":"h1"}]}`), "", false)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "componentId")
}

func TestApplyComponentID_Errors(t *testing.T) {
	_, err := ApplyComponentID([]byte("not json"), testComponentID, false)
	assert.Error(t, err)
	_, err = ApplyComponentID([]byte(`{"components":"nope"}`), testComponentID, false)
	assert.Error(t, err)
}
