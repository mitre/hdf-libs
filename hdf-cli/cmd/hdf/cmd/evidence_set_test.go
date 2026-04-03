//nolint:dupl
package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testEvidencePackage = `{
	"name": "Test Evidence",
	"contents": [{"type": "results", "uri": "results.json"}]
}`

func writeTestEvidence(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(testEvidencePackage), 0o644))
	return path
}

func TestEvidenceSet_Name(t *testing.T) {
	path := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "set", path, "--name", "Q2 Evidence")
	require.NoError(t, err)

	data, _ := os.ReadFile(path)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "Q2 Evidence", doc["name"])
}

func TestEvidenceSet_PackageID(t *testing.T) {
	path := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "set", path, "--package-id", "550e8400-e29b-41d4-a716-446655440000")
	require.NoError(t, err)

	data, _ := os.ReadFile(path)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", doc["packageId"])
}

func TestEvidenceSet_UnsetRequired(t *testing.T) {
	path := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "set", path, "--unset", "contents")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required field")
}

func TestEvidenceSet_NoFlags(t *testing.T) {
	path := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "set", path)
	assert.Error(t, err)
}
