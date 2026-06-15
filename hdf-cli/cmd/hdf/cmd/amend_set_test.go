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

const testAmendmentsForSet = `{
	"name": "Test Waivers",
	"overrides": [
		{
			"type": "waiver",
			"requirementId": "SV-001",
			"status": "notApplicable",
			"reason": "Test waiver",
			"appliedBy": {"type": "email", "identifier": "test@example.org"},
			"appliedAt": "2026-01-01T00:00:00Z",
			"expiresAt": "2027-01-01T00:00:00Z"
		}
	]
}`

func writeTestAmendments(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "amendments.json")
	require.NoError(t, os.WriteFile(path, []byte(testAmendmentsForSet), 0o644))
	return path
}

func TestAmendSet_Name(t *testing.T) {
	path := writeTestAmendments(t)
	_, _, err := executeCommand("amend", "set", path, "--name", "Q2 Waivers")
	require.NoError(t, err)

	data, _ := os.ReadFile(path)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "Q2 Waivers", doc["name"])
}

func TestAmendSet_AmendmentID(t *testing.T) {
	path := writeTestAmendments(t)
	_, _, err := executeCommand("amend", "set", path, "--amendment-id", "550e8400-e29b-41d4-a716-446655440000")
	require.NoError(t, err)

	data, _ := os.ReadFile(path)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", doc["amendmentId"])
}

func TestAmendSet_UnsetRequired(t *testing.T) {
	path := writeTestAmendments(t)
	_, _, err := executeCommand("amend", "set", path, "--unset", "overrides")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required field")
}

func TestAmendSet_NoFlags(t *testing.T) {
	path := writeTestAmendments(t)
	_, _, err := executeCommand("amend", "set", path)
	assert.Error(t, err)
}
