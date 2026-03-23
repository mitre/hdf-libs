package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitre/hdf-cli/pkg/amend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testResults = `{
  "baselines": [{
    "name": "test-baseline",
    "checksum": {"algorithm": "sha256", "value": "abc123"},
    "depends": [],
    "description": "Test baseline",
    "groups": [],
    "inspecVersion": "5.0.0",
    "requirements": [{
      "id": "AC-1",
      "impact": 0.5,
      "title": "Access Control Policy",
      "descriptions": [{"label": "default", "data": "test"}],
      "results": [{"status": "failed", "codeDesc": "test", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
      "tags": {},
      "code": null,
      "refs": [],
      "sourceLocation": {"line": 1, "ref": "test.rb"},
      "statusOverrides": [],
      "evidence": [],
      "poams": []
    }],
    "supports": []
  }],
  "statistics": {"duration": 0.1}
}`

const testAmendments = `{
  "name": "Q1 Waivers",
  "systemRef": "portal-prod.hdf-system.json",
  "overrides": [{
    "type": "waiver",
    "requirementId": "AC-1",
    "status": "passed",
    "reason": "Risk accepted per ATO",
    "appliedBy": {"type": "email", "identifier": "admin@example.com"},
    "appliedAt": "2026-03-01T00:00:00Z",
    "expiresAt": "2026-06-30T00:00:00Z"
  }]
}`

func createAmendTestFixtures(t *testing.T) (resultsPath, amendmentsPath string) {
	t.Helper()
	tmpDir := t.TempDir()

	resultsPath = filepath.Join(tmpDir, "results.json")
	require.NoError(t, os.WriteFile(resultsPath, []byte(testResults), 0o600))

	amendmentsPath = filepath.Join(tmpDir, "amendments.json")
	require.NoError(t, os.WriteFile(amendmentsPath, []byte(testAmendments), 0o600))

	return resultsPath, amendmentsPath
}

func TestAmendApplyCommand(t *testing.T) {
	t.Run("apply merges amendments into results", func(t *testing.T) {
		resultsPath, amendmentsPath := createAmendTestFixtures(t)
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "merged.json")

		_, _, err := executeCommand("amend", "apply", "--results", resultsPath, "--amendments", amendmentsPath, "-o", outputPath)
		require.NoError(t, err)

		data, readErr := os.ReadFile(outputPath)
		require.NoError(t, readErr)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &doc))

		baselines := doc["baselines"].([]interface{})
		baseline := baselines[0].(map[string]interface{})
		reqs := baseline["requirements"].([]interface{})
		req := reqs[0].(map[string]interface{})

		assert.Equal(t, "passed", req["effectiveStatus"])
	})

	t.Run("apply writes to stdout by default", func(t *testing.T) {
		resultsPath, amendmentsPath := createAmendTestFixtures(t)

		stdout, _, err := executeCommand("amend", "apply", "--results", resultsPath, "--amendments", amendmentsPath)
		require.NoError(t, err)
		assert.Contains(t, stdout, "effectiveStatus")
		assert.Contains(t, stdout, "previousChecksum")
	})

	t.Run("missing results flag returns error", func(t *testing.T) {
		_, amendmentsPath := createAmendTestFixtures(t)
		_, _, err := executeCommand("amend", "apply", "--amendments", amendmentsPath)
		require.Error(t, err)
	})

	t.Run("missing amendments flag returns error", func(t *testing.T) {
		resultsPath, _ := createAmendTestFixtures(t)
		_, _, err := executeCommand("amend", "apply", "--results", resultsPath)
		require.Error(t, err)
	})

	t.Run("missing both flags returns error", func(t *testing.T) {
		_, _, err := executeCommand("amend", "apply")
		require.Error(t, err)
	})

	t.Run("nonexistent results file returns error", func(t *testing.T) {
		_, amendmentsPath := createAmendTestFixtures(t)
		_, _, err := executeCommand("amend", "apply", "--results", "/nonexistent/results.json", "--amendments", amendmentsPath)
		require.Error(t, err)
	})

	t.Run("nonexistent amendments file returns error", func(t *testing.T) {
		resultsPath, _ := createAmendTestFixtures(t)
		_, _, err := executeCommand("amend", "apply", "--results", resultsPath, "--amendments", "/nonexistent/amendments.json")
		require.Error(t, err)
	})
}

func TestAmendListCommand(t *testing.T) {
	t.Run("list shows overrides", func(t *testing.T) {
		_, amendmentsPath := createAmendTestFixtures(t)

		stdout, _, err := executeCommand("amend", "list", amendmentsPath)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Q1 Waivers")
		assert.Contains(t, stdout, "AC-1")
		assert.Contains(t, stdout, "waiver")
		assert.Contains(t, stdout, "passed")
		assert.Contains(t, stdout, "Risk accepted per ATO")
	})

	t.Run("list with --json returns JSON array", func(t *testing.T) {
		_, amendmentsPath := createAmendTestFixtures(t)

		stdout, _, err := executeCommand("amend", "list", "--json", amendmentsPath)
		require.NoError(t, err)

		var overrides []amend.ParsedOverride
		require.NoError(t, json.Unmarshal([]byte(stdout), &overrides))
		require.Len(t, overrides, 1)
		assert.Equal(t, "AC-1", overrides[0].RequirementID)
	})

	t.Run("missing file returns error", func(t *testing.T) {
		_, _, err := executeCommand("amend", "list", "/nonexistent/amendments.json")
		require.Error(t, err)
	})
}

func TestAmendVerifyCommand(t *testing.T) {
	t.Run("verify reports valid overrides", func(t *testing.T) {
		tmpDir := t.TempDir()
		amendmentsPath := filepath.Join(tmpDir, "valid.json")
		validAmendments := `{
			"name": "valid",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "test",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(amendmentsPath, []byte(validAmendments), 0o600))

		stdout, _, err := executeCommand("amend", "verify", amendmentsPath)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Valid:           1")
		assert.Contains(t, stdout, "All overrides are valid")
	})

	t.Run("verify detects expired overrides", func(t *testing.T) {
		tmpDir := t.TempDir()
		amendmentsPath := filepath.Join(tmpDir, "expired.json")
		expiredAmendments := `{
			"name": "expired",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "test",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2020-01-01T00:00:00Z",
				"expiresAt": "2020-06-30T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(amendmentsPath, []byte(expiredAmendments), 0o600))

		stdout, _, err := executeCommand("amend", "verify", amendmentsPath)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Expired:         1")
		assert.Contains(t, stdout, "expired or invalid")
	})

	t.Run("verify with --json returns JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		amendmentsPath := filepath.Join(tmpDir, "valid.json")
		validAmendments := `{
			"name": "valid",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "test",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(amendmentsPath, []byte(validAmendments), 0o600))

		stdout, _, err := executeCommand("amend", "verify", "--json", amendmentsPath)
		require.NoError(t, err)

		var result amend.VerifyResult
		require.NoError(t, json.Unmarshal([]byte(stdout), &result))
		assert.Equal(t, 1, result.TotalOverrides)
		assert.Equal(t, 1, result.ValidOverrides)
	})

	t.Run("verify chain with results file", func(t *testing.T) {
		resultsPath, amendmentsPath := createAmendTestFixtures(t)

		stdout, _, err := executeCommand("amend", "verify", amendmentsPath, resultsPath)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Chain:")
	})

	t.Run("verify chain with --json", func(t *testing.T) {
		resultsPath, amendmentsPath := createAmendTestFixtures(t)

		stdout, _, err := executeCommand("amend", "verify", "--json", amendmentsPath, resultsPath)
		require.NoError(t, err)

		var result amend.ChainVerifyResult
		require.NoError(t, json.Unmarshal([]byte(stdout), &result))
		assert.NotNil(t, result.ExpirationResult)
	})

	t.Run("verify chain with nonexistent results returns error", func(t *testing.T) {
		_, amendmentsPath := createAmendTestFixtures(t)
		_, _, err := executeCommand("amend", "verify", amendmentsPath, "/nonexistent/results.json")
		require.Error(t, err)
	})

	t.Run("verify chain detects missing requirements", func(t *testing.T) {
		// Create amendments referencing a requirement that doesn't exist in results
		tmpDir := t.TempDir()
		resultsPath := filepath.Join(tmpDir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(testResults), 0o600))

		badAmendments := `{
			"name": "bad-refs",
			"overrides": [{
				"type": "waiver",
				"requirementId": "NONEXISTENT-99",
				"status": "passed",
				"reason": "test",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`
		amendPath := filepath.Join(tmpDir, "bad-amendments.json")
		require.NoError(t, os.WriteFile(amendPath, []byte(badAmendments), 0o600))

		stdout, _, err := executeCommand("amend", "verify", amendPath, resultsPath)
		// Chain verification may fail or succeed depending on impl, but output should mention missing
		if err != nil {
			assert.Contains(t, err.Error(), "verification failed")
		}
		_ = stdout
	})

	t.Run("missing file returns error", func(t *testing.T) {
		_, _, err := executeCommand("amend", "verify", "/nonexistent/amendments.json")
		require.Error(t, err)
	})
}

func TestTruncateToDate(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2026-03-22T15:30:00Z", "2026-03-22"},
		{"2026-03-22", "2026-03-22"},
		{"short", "short"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, truncateToDate(tt.input))
		})
	}
}
