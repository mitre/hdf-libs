package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const systemFixture = `{
  "name": "Portal-Prod",
  "systemId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "authorizationStatus": "authorized",
  "categorizationLevel": "moderate",
  "description": "Production portal system",
  "owner": {"type": "email", "identifier": "platform-team@agency.gov"},
  "components": [
    {
      "name": "WebTier",
      "type": "application",
      "baselineRefs": ["RHEL9-STIG", "Container-STIG"],
      "targetSelector": {"labels.component": "WebTier"},
      "owner": {"type": "email", "identifier": "web-team@agency.gov"}
    },
    {
      "name": "DatabaseTier",
      "type": "database",
      "baselineRefs": ["PostgreSQL-STIG"]
    },
    {
      "name": "CacheTier",
      "type": "application",
      "description": "Redis cache layer"
    }
  ],
  "dataFlows": [
    {
      "from": "web-tier-id",
      "to": "db-tier-id",
      "protocol": "JDBC",
      "description": "Web tier to database"
    }
  ]
}`

func writeSystemFixture(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "system.json")
	require.NoError(t, os.WriteFile(p, []byte(systemFixture), 0o600))
	return p
}

func TestSystemInfoCommand(t *testing.T) { //nolint:dupl
	t.Run("displays system info in human-readable format", func(t *testing.T) {
		fixture := writeSystemFixture(t)
		stdout, _, err := executeCommand("system", "info", fixture)
		require.NoError(t, err)

		assert.Contains(t, stdout, "System: Portal-Prod")
		assert.Contains(t, stdout, "Authorization: authorized")
		assert.Contains(t, stdout, "Categorization: moderate")
		assert.Contains(t, stdout, "Description: Production portal system")
		assert.Contains(t, stdout, "Components (3):")
		assert.Contains(t, stdout, "WebTier (application)")
		assert.Contains(t, stdout, "Baselines: RHEL9-STIG, Container-STIG")
		assert.Contains(t, stdout, "Target selector: {labels.component: WebTier}")
		assert.Contains(t, stdout, "DatabaseTier (database)")
		assert.Contains(t, stdout, "CacheTier (application)")
		assert.Contains(t, stdout, "System ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
		assert.Contains(t, stdout, "Owner: platform-team@agency.gov (email)")
		assert.Contains(t, stdout, "Owner: web-team@agency.gov")
		assert.Contains(t, stdout, "Redis cache layer")
		assert.Contains(t, stdout, "Data Flows (1):")
		assert.Contains(t, stdout, "web-tier-id")
		assert.Contains(t, stdout, "db-tier-id")
		assert.Contains(t, stdout, "JDBC")
	})

	t.Run("displays system info in JSON format", func(t *testing.T) {
		fixture := writeSystemFixture(t)
		stdout, _, err := executeCommand("system", "info", "--json", fixture)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &doc))
		assert.Equal(t, "Portal-Prod", doc["name"])
		assert.Equal(t, "authorized", doc["authorizationStatus"])
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, _, err := executeCommand("system", "info", "/nonexistent/file.json")
		require.Error(t, err)
	})

	t.Run("returns usage error with no args", func(t *testing.T) {
		_, _, err := executeCommand("system", "info")
		require.Error(t, err)
	})
}

func TestSystemSet(t *testing.T) {
	// Helper: write fixture and return path
	writeFixture := func(t *testing.T) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "system.json")
		require.NoError(t, os.WriteFile(p, []byte(`{
			"name": "Original",
			"components": [{"name": "App", "type": "application"}]
		}`), 0o600))
		return p
	}

	readDoc := func(t *testing.T, path string) map[string]interface{} {
		t.Helper()
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &doc))
		return doc
	}

	t.Run("adds owner to system without one", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--owner", "team@agency.gov")
		require.NoError(t, err)

		doc := readDoc(t, f)
		owner, ok := doc["owner"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "email", owner["type"])
		assert.Equal(t, "team@agency.gov", owner["identifier"])
	})

	t.Run("updates existing owner", func(t *testing.T) {
		f := writeFixture(t)
		// Set initial owner
		_, _, err := executeCommand("system", "set", f, "--owner", "old@agency.gov")
		require.NoError(t, err)
		// Update it
		_, _, err = executeCommand("system", "set", f, "--owner", "new@agency.gov")
		require.NoError(t, err)

		doc := readDoc(t, f)
		owner := doc["owner"].(map[string]interface{})
		assert.Equal(t, "new@agency.gov", owner["identifier"])
	})

	t.Run("sets plain text owner", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--owner", "Platform Team")
		require.NoError(t, err)

		doc := readDoc(t, f)
		owner := doc["owner"].(map[string]interface{})
		assert.Equal(t, "simple", owner["type"])
		assert.Equal(t, "Platform Team", owner["identifier"])
	})

	t.Run("sets description", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--description", "Production portal")
		require.NoError(t, err)

		doc := readDoc(t, f)
		assert.Equal(t, "Production portal", doc["description"])
	})

	t.Run("sets name", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--name", "New Name")
		require.NoError(t, err)

		doc := readDoc(t, f)
		assert.Equal(t, "New Name", doc["name"])
	})

	t.Run("sets system-id", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--system-id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
		require.NoError(t, err)

		doc := readDoc(t, f)
		assert.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", doc["systemId"])
	})

	t.Run("sets multiple fields at once", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--owner", "team@agency.gov", "--description", "Prod system", "--name", "Portal")
		require.NoError(t, err)

		doc := readDoc(t, f)
		assert.Equal(t, "Portal", doc["name"])
		assert.Equal(t, "Prod system", doc["description"])
		owner := doc["owner"].(map[string]interface{})
		assert.Equal(t, "team@agency.gov", owner["identifier"])
	})

	t.Run("preserves existing fields", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--owner", "team@agency.gov")
		require.NoError(t, err)

		doc := readDoc(t, f)
		assert.Equal(t, "Original", doc["name"])
		components, ok := doc["components"].([]interface{})
		require.True(t, ok)
		assert.Len(t, components, 1)
	})

	t.Run("writes to output file when -o specified", func(t *testing.T) {
		f := writeFixture(t)
		out := filepath.Join(t.TempDir(), "updated.json")
		_, _, err := executeCommand("system", "set", f, "--owner", "team@agency.gov", "-o", out)
		require.NoError(t, err)

		doc := readDoc(t, out)
		assert.Equal(t, "team@agency.gov", doc["owner"].(map[string]interface{})["identifier"])
		// Original unchanged
		origDoc := readDoc(t, f)
		assert.Nil(t, origDoc["owner"])
	})

	t.Run("errors with no flags", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f)
		assert.Error(t, err)
	})

	t.Run("errors with missing file", func(t *testing.T) {
		_, _, err := executeCommand("system", "set", "/nonexistent.json", "--owner", "x")
		assert.Error(t, err)
	})

	t.Run("unsets a field", func(t *testing.T) {
		f := writeFixture(t)
		// Set owner first
		_, _, err := executeCommand("system", "set", f, "--owner", "team@agency.gov")
		require.NoError(t, err)
		// Unset it
		_, _, err = executeCommand("system", "set", f, "--unset", "owner")
		require.NoError(t, err)

		doc := readDoc(t, f)
		assert.Nil(t, doc["owner"])
	})

	t.Run("unsets multiple fields", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--owner", "x", "--description", "y")
		require.NoError(t, err)
		_, _, err = executeCommand("system", "set", f, "--unset", "owner", "--unset", "description")
		require.NoError(t, err)

		doc := readDoc(t, f)
		assert.Nil(t, doc["owner"])
		assert.Nil(t, doc["description"])
	})

	t.Run("refuses to unset required field name", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--unset", "name")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("refuses to unset required field components", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--unset", "components")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("unset and set in same invocation", func(t *testing.T) {
		f := writeFixture(t)
		_, _, err := executeCommand("system", "set", f, "--owner", "old", "--description", "old desc")
		require.NoError(t, err)
		_, _, err = executeCommand("system", "set", f, "--unset", "description", "--owner", "new@agency.gov")
		require.NoError(t, err)

		doc := readDoc(t, f)
		assert.Nil(t, doc["description"])
		owner := doc["owner"].(map[string]interface{})
		assert.Equal(t, "new@agency.gov", owner["identifier"])
	})
}
