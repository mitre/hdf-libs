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
	assert.Nil(t, plan["type"]) // type is optional, not assumed
	assert.Equal(t, sysFile, plan["systemRef"])
	// planId should be auto-generated
	sysCreatePlanID, ok := plan["planId"].(string)
	assert.True(t, ok, "planId should be present")
	assert.Len(t, sysCreatePlanID, 36)

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

func TestPlanCreate_Standalone(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "plan.json")
	_, _, err := executeCommand("plan", "create", "--name", "RHEL9 Assessment", "--baseline", "RHEL9-STIG", "-o", outFile)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var plan map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &plan))
	assert.Equal(t, "RHEL9 Assessment", plan["name"])
	assert.Nil(t, plan["systemRef"]) // no system reference
	// planId should be auto-generated
	planID, ok := plan["planId"].(string)
	assert.True(t, ok, "planId should be present")
	assert.Len(t, planID, 36, "planId should be a UUID")
	assessments, ok := plan["assessments"].([]interface{})
	require.True(t, ok)
	assert.Len(t, assessments, 1)
	first := assessments[0].(map[string]interface{})
	assert.Equal(t, "RHEL9-STIG", first["baselineRef"])
}

func TestPlanCreate_StandaloneRequiresBothFlags(t *testing.T) {
	// --name without --baseline
	_, _, err := executeCommand("plan", "create", "--name", "Test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "baseline")

	// --baseline without --name
	_, _, err = executeCommand("plan", "create", "--baseline", "RHEL9-STIG")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--name")
}

func TestPlanCreate_NoArgsNoFlags(t *testing.T) {
	_, _, err := executeCommand("plan", "create")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "system file")
}
