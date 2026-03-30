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

const testPlan = `{
	"name": "Test Plan",
	"assessments": [{"baselineRef": "RHEL9-STIG"}]
}`

func writeTestPlan(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	require.NoError(t, os.WriteFile(path, []byte(testPlan), 0o644))
	return path
}

func readPlanDoc(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc
}

func TestPlanSet_Name(t *testing.T) {
	planPath := writeTestPlan(t)
	_, _, err := executeCommand("plan", "set", planPath, "--name", "Updated Plan")
	require.NoError(t, err)

	doc := readPlanDoc(t, planPath)
	assert.Equal(t, "Updated Plan", doc["name"])
}

func TestPlanSet_Description(t *testing.T) {
	planPath := writeTestPlan(t)
	_, _, err := executeCommand("plan", "set", planPath, "--description", "Monthly scan")
	require.NoError(t, err)

	doc := readPlanDoc(t, planPath)
	assert.Equal(t, "Monthly scan", doc["description"])
}

func TestPlanSet_PlanID(t *testing.T) {
	planPath := writeTestPlan(t)
	_, _, err := executeCommand("plan", "set", planPath, "--plan-id", "550e8400-e29b-41d4-a716-446655440000")
	require.NoError(t, err)

	doc := readPlanDoc(t, planPath)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", doc["planId"])
}

func TestPlanSet_SystemRef(t *testing.T) {
	planPath := writeTestPlan(t)
	_, _, err := executeCommand("plan", "set", planPath, "--system-ref", "portal-prod.hdf-system.json")
	require.NoError(t, err)

	doc := readPlanDoc(t, planPath)
	assert.Equal(t, "portal-prod.hdf-system.json", doc["systemRef"])
}

func TestPlanSet_Version(t *testing.T) {
	planPath := writeTestPlan(t)
	_, _, err := executeCommand("plan", "set", planPath, "--version", "2.0.0")
	require.NoError(t, err)

	doc := readPlanDoc(t, planPath)
	assert.Equal(t, "2.0.0", doc["version"])
}

func TestPlanSet_Unset(t *testing.T) {
	// Start with a plan that has description and version
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	planWithExtras := `{
		"name": "Test Plan",
		"description": "Remove me",
		"version": "1.0.0",
		"assessments": [{"baselineRef": "RHEL9-STIG"}]
	}`
	require.NoError(t, os.WriteFile(planPath, []byte(planWithExtras), 0o644))

	_, _, err := executeCommand("plan", "set", planPath, "--unset", "description", "--unset", "version")
	require.NoError(t, err)

	doc := readPlanDoc(t, planPath)
	assert.Nil(t, doc["description"])
	assert.Nil(t, doc["version"])
	assert.Equal(t, "Test Plan", doc["name"]) // name preserved
}

func TestPlanSet_UnsetRequired(t *testing.T) {
	planPath := writeTestPlan(t)
	_, _, err := executeCommand("plan", "set", planPath, "--unset", "name")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required field")
}

func TestPlanSet_OutputFile(t *testing.T) {
	planPath := writeTestPlan(t)
	outputPath := filepath.Join(t.TempDir(), "updated.json")

	_, _, err := executeCommand("plan", "set", planPath, "--name", "New Name", "-o", outputPath)
	require.NoError(t, err)

	// Original unchanged
	origDoc := readPlanDoc(t, planPath)
	assert.Equal(t, "Test Plan", origDoc["name"])

	// Output has update
	newDoc := readPlanDoc(t, outputPath)
	assert.Equal(t, "New Name", newDoc["name"])
}

func TestPlanSet_NoFlags(t *testing.T) {
	planPath := writeTestPlan(t)
	_, _, err := executeCommand("plan", "set", planPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one field flag")
}
