package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const planFixture = `{
  "name": "quarterly-assessment-plan",
  "type": "automated",
  "systemRef": "portal-prod.hdf-system.json",
  "assessments": [
    {
      "baselineRef": "RHEL9-STIG",
      "runner": {"name": "cinc-auditor"}
    },
    {
      "baselineRef": "PostgreSQL-STIG",
      "runner": {"name": "openscap"}
    }
  ],
  "schedule": {
    "cron": "0 0 1 */3 *"
  }
}`

func writePlanFixture(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "plan.json")
	require.NoError(t, os.WriteFile(p, []byte(planFixture), 0o600))
	return p
}

func TestPlanInfoCommand(t *testing.T) {
	t.Run("displays plan info in human-readable format", func(t *testing.T) {
		fixture := writePlanFixture(t)
		stdout, _, err := executeCommand("plan", "info", fixture)
		require.NoError(t, err)

		assert.Contains(t, stdout, "Plan: quarterly-assessment-plan")
		assert.Contains(t, stdout, "Type: automated")
		assert.Contains(t, stdout, "System: portal-prod.hdf-system.json")
		assert.Contains(t, stdout, "Assessments (2):")
		assert.Contains(t, stdout, "1. Baseline: RHEL9-STIG")
		assert.Contains(t, stdout, "Runner: cinc-auditor")
		assert.Contains(t, stdout, "2. Baseline: PostgreSQL-STIG")
		assert.Contains(t, stdout, "Runner: openscap")
		assert.Contains(t, stdout, "Schedule: 0 0 1 */3 *  (quarterly)")
	})

	t.Run("displays plan info in JSON format", func(t *testing.T) {
		fixture := writePlanFixture(t)
		stdout, _, err := executeCommand("plan", "info", "--json", fixture)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &doc))
		assert.Equal(t, "quarterly-assessment-plan", doc["name"])
		assert.Equal(t, "automated", doc["type"])
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, _, err := executeCommand("plan", "info", "/nonexistent/file.json")
		require.Error(t, err)
	})

	t.Run("returns usage error with no args", func(t *testing.T) {
		_, _, err := executeCommand("plan", "info")
		require.Error(t, err)
	})
}

func TestDescribeCron(t *testing.T) {
	assert.Equal(t, "daily", describeCron("0 0 * * *"))
	assert.Equal(t, "weekly", describeCron("0 0 * * 0"))
	assert.Equal(t, "monthly", describeCron("0 0 1 * *"))
	assert.Equal(t, "quarterly", describeCron("0 0 1 */3 *"))
	assert.Equal(t, "annually", describeCron("0 0 1 1 *"))
	assert.Equal(t, "", describeCron("5 4 * * *"))
}
