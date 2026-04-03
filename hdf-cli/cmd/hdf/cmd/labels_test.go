package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	noTargetsJSON    = `{"baselines": []}`
	singleTargetJSON = `{"components": [{"name": "h1", "type": "host"}]}`
)

func TestParseLabelsFlag(t *testing.T) {
	t.Run("valid single label", func(t *testing.T) {
		labels, err := parseLabelsFlag([]string{"system=Portal"})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"system": "Portal"}, labels)
	})

	t.Run("valid multiple labels", func(t *testing.T) {
		labels, err := parseLabelsFlag([]string{"system=Portal", "environment=production"})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			"system":      "Portal",
			"environment": "production",
		}, labels)
	})

	t.Run("value with equals sign", func(t *testing.T) {
		labels, err := parseLabelsFlag([]string{"key=val=ue"})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"key": "val=ue"}, labels)
	})

	t.Run("empty value", func(t *testing.T) {
		labels, err := parseLabelsFlag([]string{"key="})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"key": ""}, labels)
	})

	t.Run("invalid no equals sign", func(t *testing.T) {
		_, err := parseLabelsFlag([]string{"noequalssign"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key=value format")
	})

	t.Run("invalid empty key", func(t *testing.T) {
		_, err := parseLabelsFlag([]string{"=value"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key must not be empty")
	})

	t.Run("empty input", func(t *testing.T) {
		labels, err := parseLabelsFlag([]string{})
		require.NoError(t, err)
		assert.Empty(t, labels)
	})
}

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
		result, err := applyLabels([]byte(input), labels)
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
		result, err := applyLabels([]byte(input), labels)
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
		result, err := applyLabels([]byte(input), labels)
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
		result, err := applyLabels([]byte(input), labels)
		require.NoError(t, err)
		// Should return unchanged
		assert.JSONEq(t, input, string(result))
	})

	t.Run("empty labels map is no-op", func(t *testing.T) {
		input := singleTargetJSON
		result, err := applyLabels([]byte(input), map[string]string{})
		require.NoError(t, err)
		assert.Equal(t, input, string(result))
	})

	t.Run("invalid JSON input", func(t *testing.T) {
		_, err := applyLabels([]byte("not json"), map[string]string{"k": "v"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JSON")
	})

	t.Run("targets is not an array", func(t *testing.T) {
		input := `{"components": "not-an-array"}`
		_, err := applyLabels([]byte(input), map[string]string{"k": "v"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not an array")
	})
}

func TestRemoveLabels(t *testing.T) {
	t.Run("remove existing keys", func(t *testing.T) {
		input := `{
  "components": [
    {"name": "host1", "type": "host", "labels": {"env": "prod", "team": "sec"}}
  ]
}`
		result, err := removeLabels([]byte(input), []string{"env"})
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &doc))

		targets := doc["components"].([]interface{})
		target := targets[0].(map[string]interface{})
		targetLabels := target["labels"].(map[string]interface{})
		assert.NotContains(t, targetLabels, "env")
		assert.Equal(t, "sec", targetLabels["team"])
	})

	t.Run("remove nonexistent keys is silent", func(t *testing.T) {
		input := `{
  "components": [
    {"name": "host1", "type": "host", "labels": {"env": "prod"}}
  ]
}`
		result, err := removeLabels([]byte(input), []string{"nonexistent"})
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
		result, err := removeLabels([]byte(input), []string{"env"})
		require.NoError(t, err)
		assert.JSONEq(t, input, string(result))
	})

	t.Run("target without labels field", func(t *testing.T) {
		input := singleTargetJSON
		result, err := removeLabels([]byte(input), []string{"env"})
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &doc))
		// Should succeed without error; target unchanged except re-serialization
		targets := doc["components"].([]interface{})
		target := targets[0].(map[string]interface{})
		assert.Equal(t, "h1", target["name"])
	})

	t.Run("empty keys list is no-op", func(t *testing.T) {
		input := singleTargetJSON
		result, err := removeLabels([]byte(input), []string{})
		require.NoError(t, err)
		assert.Equal(t, input, string(result))
	})

	t.Run("invalid JSON input", func(t *testing.T) {
		_, err := removeLabels([]byte("not json"), []string{"k"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JSON")
	})
}

func TestExtractTargetLabels(t *testing.T) {
	t.Run("extracts labels from targets", func(t *testing.T) {
		input := `{
  "components": [
    {"name": "host1", "type": "host", "labels": {"env": "prod"}},
    {"name": "host2", "type": "container"}
  ]
}`
		infos, err := extractComponentLabels([]byte(input))
		require.NoError(t, err)
		require.Len(t, infos, 2)

		assert.Equal(t, "host1", infos[0].Name)
		assert.Equal(t, "host", infos[0].Type)
		assert.Equal(t, "prod", infos[0].Labels["env"])

		assert.Equal(t, "host2", infos[1].Name)
		assert.Equal(t, "container", infos[1].Type)
		assert.Empty(t, infos[1].Labels)
	})

	t.Run("no targets returns nil", func(t *testing.T) {
		input := noTargetsJSON
		infos, err := extractComponentLabels([]byte(input))
		require.NoError(t, err)
		assert.Nil(t, infos)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := extractComponentLabels([]byte("nope"))
		require.Error(t, err)
	})
}

func TestFormatLabelPairs(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		assert.Equal(t, "(none)", formatLabelPairs(map[string]string{}))
	})

	t.Run("sorted output", func(t *testing.T) {
		labels := map[string]string{"z": "1", "a": "2"}
		assert.Equal(t, "a=2, z=1", formatLabelPairs(labels))
	})
}
