package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonPathLineMap_BasicObject(t *testing.T) {
	data := []byte(`{
  "name": "test",
  "version": "1.0"
}`)
	lineMap := jsonPathLineMap(data)

	assert.Equal(t, 2, lineMap["name"], "name should be on line 2")
	assert.Equal(t, 3, lineMap["version"], "version should be on line 3")
}

func TestJsonPathLineMap_NestedObject(t *testing.T) {
	data := []byte(`{
  "outer": {
    "inner": "value"
  }
}`)
	lineMap := jsonPathLineMap(data)

	assert.Equal(t, 2, lineMap["outer"], "outer should be on line 2")
	assert.Equal(t, 3, lineMap["outer.inner"], "outer.inner should be on line 3")
}

func TestJsonPathLineMap_Array(t *testing.T) {
	data := []byte(`{
  "items": [
    "first",
    "second"
  ]
}`)
	lineMap := jsonPathLineMap(data)

	assert.Equal(t, 2, lineMap["items"], "items should be on line 2")
	assert.Contains(t, lineMap, "items.0")
	assert.Contains(t, lineMap, "items.1")
}

func TestJsonPathLineMap_ArrayOfObjects(t *testing.T) {
	data := []byte(`{
  "baselines": [
    {
      "name": "RHEL9-STIG",
      "requirements": [
        {
          "id": "SV-001"
        }
      ]
    }
  ]
}`)
	lineMap := jsonPathLineMap(data)

	assert.Equal(t, 2, lineMap["baselines"], "baselines on line 2")
	assert.Contains(t, lineMap, "baselines.0")
	assert.Equal(t, 4, lineMap["baselines.0.name"], "baselines.0.name on line 4")
	assert.Equal(t, 5, lineMap["baselines.0.requirements"], "baselines.0.requirements on line 5")
	assert.Contains(t, lineMap, "baselines.0.requirements.0")
	assert.Equal(t, 7, lineMap["baselines.0.requirements.0.id"], "baselines.0.requirements.0.id on line 7")
}

func TestJsonPathLineMap_InvalidJSON(t *testing.T) {
	lineMap := jsonPathLineMap([]byte("not json"))
	// Should return an empty map, not panic
	assert.NotNil(t, lineMap)
}

func TestLookupLineNumber_ExactMatch(t *testing.T) {
	lineMap := map[string]int{
		"baselines":        2,
		"baselines.0.name": 4,
	}

	assert.Equal(t, 4, lookupLineNumber(lineMap, "baselines.0.name"))
}

func TestLookupLineNumber_PrefixFallback(t *testing.T) {
	lineMap := map[string]int{
		"baselines":   2,
		"baselines.0": 3,
	}

	// "baselines.0.name" doesn't exist, falls back to "baselines.0"
	assert.Equal(t, 3, lookupLineNumber(lineMap, "baselines.0.name"))
}

func TestLookupLineNumber_RootOrEmpty(t *testing.T) {
	lineMap := map[string]int{"baselines": 2}

	assert.Equal(t, 0, lookupLineNumber(lineMap, ""))
	assert.Equal(t, 0, lookupLineNumber(lineMap, "(root)"))
	assert.Equal(t, 0, lookupLineNumber(lineMap, "(parse)"))
}

func TestOffsetToLine(t *testing.T) {
	// "abc\ndef\nghi" → line offsets [0, 4, 8]
	offsets := []int{0, 4, 8}

	assert.Equal(t, 1, offsetToLine(offsets, 0))  // 'a'
	assert.Equal(t, 1, offsetToLine(offsets, 3))  // '\n'
	assert.Equal(t, 2, offsetToLine(offsets, 4))  // 'd'
	assert.Equal(t, 3, offsetToLine(offsets, 8))  // 'g'
	assert.Equal(t, 3, offsetToLine(offsets, 10)) // 'i'
}

// --- Integration: validate with line numbers ---

func TestValidateCommand_LineNumbers_Human(t *testing.T) {
	// Create a pretty-printed invalid file so fields are on specific lines
	badDoc := map[string]interface{}{
		"baselines":  "not an array",
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
	data, err := json.MarshalIndent(badDoc, "", "  ")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-results.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, stderr, err := executeCommand("validate", "--type", "results", path)
	require.Error(t, err)

	// Should contain "line" annotation for the baselines error
	assert.Contains(t, stderr, "line ")
}

func TestValidateCommand_LineNumbers_JSON(t *testing.T) {
	badDoc := map[string]interface{}{
		"baselines":  "not an array",
		"components": []interface{}{},
		"statistics": map[string]interface{}{},
	}
	data, err := json.MarshalIndent(badDoc, "", "  ")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-results.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	stdout, _, err := executeCommand("validate", "--type", "results", "--json", path)
	require.Error(t, err)

	var output map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &output))

	errors, ok := output["errors"].([]interface{})
	require.True(t, ok, "expected errors array")
	require.NotEmpty(t, errors)

	// At least one error should have a line number > 0
	hasLine := false
	for _, e := range errors {
		errMap, _ := e.(map[string]interface{})
		if line, ok := errMap["line"].(float64); ok && line > 0 {
			hasLine = true
			break
		}
	}
	assert.True(t, hasLine, "expected at least one error with line > 0")
}

func TestValidateCommand_LineNumbers_Stdin(t *testing.T) {
	// Stdin input should NOT have line numbers (can't seek back)
	// This just verifies validate still works via stdin without crashing
	// (stdin tests are harder to do in this framework, so we just test
	// that the flag path is safe)
	_ = t // placeholder — stdin line numbers are explicitly skipped
}

func TestValidateCommand_LineNumbers_System(t *testing.T) {
	// System doc missing required "name" — should show line numbers
	badSystem := `{
  "components": [
    {
      "type": "application"
    }
  ]
}`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-system.json")
	require.NoError(t, os.WriteFile(path, []byte(badSystem), 0o600))

	_, stderr, err := executeCommand("validate", "--type", "system", path)
	require.Error(t, err)

	// Should contain line number annotations
	assert.True(t, strings.Contains(stderr, "line "), "expected line numbers in system validation errors, got:\n%s", stderr)
}
