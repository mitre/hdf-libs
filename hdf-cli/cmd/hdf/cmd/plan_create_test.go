package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	assertCreationTimestamp(t, plan)

	assert.Contains(t, plan["name"], "portal-prod")
	assert.Nil(t, plan["type"]) // type is optional, not assumed
	// plan_create normalizes systemRef via filepath.ToSlash so the schema's
	// uri-reference format check passes on Windows; assert against the
	// slash-normalized form.
	assert.Equal(t, filepath.ToSlash(sysFile), plan["systemRef"])
	// planId should be auto-generated
	sysCreatePlanID, ok := plan["planId"].(string)
	assert.True(t, ok, "planId should be present")
	assert.Len(t, sysCreatePlanID, 36)

	assessments, ok := plan["assessments"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{
		map[string]interface{}{"baselineRef": "RHEL9-STIG", "targetSelector": map[string]interface{}{"labels.component": "WebTier"}},
		map[string]interface{}{"baselineRef": "Container-STIG", "targetSelector": map[string]interface{}{"labels.component": "WebTier"}},
		map[string]interface{}{"baselineRef": "PostgreSQL-STIG"},
	}, assessments)
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

func TestPlanAssessmentsSkipMalformedEntries(t *testing.T) {
	components := []interface{}{
		nil,
		"not a component",
		map[string]interface{}{},
		map[string]interface{}{"baselineRefs": "not a list"},
		map[string]interface{}{"baselineRefs": []interface{}{}},
		map[string]interface{}{
			"baselineRefs":   []interface{}{"RHEL9-STIG", nil, 17, "Container-STIG"},
			"targetSelector": map[string]interface{}{"labels.component": "WebTier"},
		},
		map[string]interface{}{
			"baselineRefs":   []interface{}{"PostgreSQL-STIG"},
			"targetSelector": map[string]interface{}{},
		},
		map[string]interface{}{
			"baselineRefs":   []interface{}{"RHEL9-STIG"},
			"targetSelector": "not a selector",
		},
	}
	before, err := json.Marshal(components)
	require.NoError(t, err)
	assert.Equal(t, []map[string]interface{}{
		{"baselineRef": "RHEL9-STIG", "targetSelector": map[string]interface{}{"labels.component": "WebTier"}},
		{"baselineRef": "Container-STIG", "targetSelector": map[string]interface{}{"labels.component": "WebTier"}},
		{"baselineRef": "PostgreSQL-STIG"},
		{"baselineRef": "RHEL9-STIG"},
	}, assessmentsFromComponents(components))
	after, err := json.Marshal(components)
	require.NoError(t, err)
	assert.Equal(t, before, after, "building assessments must not modify the source system")
	assert.Equal(t, []map[string]interface{}{}, assessmentsFromComponents(nil))
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
	assertCreationTimestamp(t, plan)
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

// assertCreationTimestamp checks the document's root createdAt, where every
// released hdf-cli has written it and the System and Plan schemas declare it.
func assertCreationTimestamp(t *testing.T, doc map[string]interface{}) {
	t.Helper()
	createdAt, ok := doc["createdAt"].(string)
	require.True(t, ok, "root createdAt missing")
	parsed, err := time.Parse(time.RFC3339, createdAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), parsed, time.Minute)
}
