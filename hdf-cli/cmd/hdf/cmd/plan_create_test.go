package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const minimalSystemJSON = `{
  "name": "Portal Prod",
  "components": [
    {"name": "WebTier", "type": "application", "baselineRefs": ["RHEL9-STIG", "Container-STIG"], "targetSelector": {"labels.component": "WebTier"}},
    {"name": "DatabaseTier", "type": "database", "baselineRefs": ["PostgreSQL-STIG"]}
  ]
}`

func TestPlanCreate(t *testing.T) {
	sysFile := filepath.Join(t.TempDir(), "system.json")
	require.NoError(t, os.WriteFile(sysFile, []byte(minimalSystemJSON), 0o600))

	outFile := filepath.Join(t.TempDir(), "plan.json")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"plan", "create", sysFile, "-o", outFile})

	err := cmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var plan map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &plan))

	assert.Contains(t, plan["name"], "portal-prod")
	assert.Equal(t, "automated", plan["type"])
	assert.Equal(t, sysFile, plan["systemRef"])

	assessments, ok := plan["assessments"].([]interface{})
	require.True(t, ok)
	assert.Len(t, assessments, 3) // RHEL9-STIG, Container-STIG, PostgreSQL-STIG
}

func TestPlanCreate_NoBaselineRefs(t *testing.T) {
	sysFile := filepath.Join(t.TempDir(), "system.json")
	sys := `{"name": "Empty", "components": [{"name": "NoBL", "type": "application"}]}`
	require.NoError(t, os.WriteFile(sysFile, []byte(sys), 0o600))

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"plan", "create", sysFile})

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no assessments")
}

func TestPlanCreate_MissingFile(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"plan", "create", "/nonexistent/system.json"})

	err := cmd.Execute()
	assert.Error(t, err)
}
