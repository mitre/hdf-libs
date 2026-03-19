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
  "authorizationStatus": "authorized",
  "categorizationLevel": "moderate",
  "description": "Production portal system",
  "components": [
    {
      "name": "WebTier",
      "type": "application",
      "baselineRefs": ["RHEL9-STIG", "Container-STIG"],
      "targetSelector": {"labels.component": "WebTier"}
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
  "interconnections": [
    {
      "name": "External Auth Service",
      "externalSystem": "idp.example.com",
      "direction": "outbound"
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

func TestSystemInfoCommand(t *testing.T) {
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
		assert.Contains(t, stdout, "Redis cache layer")
		assert.Contains(t, stdout, "Interconnections (1):")
		assert.Contains(t, stdout, "External Auth Service (outbound)")
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
