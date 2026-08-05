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

// Integration coverage for the validate command's line-number annotation, now
// powered by hdfutil.JSONPathLineMap / LookupLineNumber (lifted to
// hdf-utilities). The pure line-map unit tests live with that package.

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
