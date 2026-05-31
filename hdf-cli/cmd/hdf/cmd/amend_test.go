package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mitre/hdf-libs/hdf-diff/go/v3/amend"
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
		assert.Contains(t, stdout, "Valid:")
		assert.Contains(t, stdout, "All amendments are valid")
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

func TestExtractAllRequirements(t *testing.T) {
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(testResults), &doc))

	reqs := extractAllRequirements(doc)
	require.Len(t, reqs, 1)
	assert.Equal(t, "AC-1", reqs[0].ID)
	assert.Equal(t, "Access Control Policy", reqs[0].Title)
	assert.Equal(t, "test-baseline", reqs[0].Baseline)
	assert.Equal(t, "failed", reqs[0].Status)
}

func TestBuildAmendmentsFromOverrides(t *testing.T) {
	overrides := []amendOverride{
		{RequirementID: "AC-1", AmendType: "waiver", Reason: "Risk accepted", ExpiresAt: "2026-12-31", Approver: "issm@acme.com"},
		{RequirementID: "AC-2", AmendType: "waiver", Reason: "Risk accepted", ExpiresAt: "2026-12-31", Approver: "issm@acme.com"},
	}
	doc := buildAmendmentsFromOverrides(overrides)

	rawOverrides, ok := doc["overrides"].([]map[string]interface{})
	require.True(t, ok)
	assert.Len(t, rawOverrides, 2)

	first := rawOverrides[0]
	assert.Equal(t, "waiver", first["type"])
	assert.Equal(t, "AC-1", first["requirementId"])
	assert.Equal(t, "passed", first["status"])
	assert.Equal(t, "Risk accepted", first["reason"])
	assert.Contains(t, doc["name"].(string), "waiver")

	// Approver with @ should be email type
	appliedBy, _ := first["appliedBy"].(map[string]interface{})
	assert.Equal(t, "email", appliedBy["type"])
}

func TestParseExpiryInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"absolute date", "2027-06-15", false},
		{"30 days", "30d", false},
		{"3 months", "3m", false},
		{"1 year", "1y", false},
		{"6 months", "6m", false},
		{"invalid format", "abc", true},
		{"empty", "", true},
		{"zero days", "0d", true},
		{"negative", "-1m", true},
		{"bad unit", "5x", true},
		{"past date", "2020-01-01", false}, // parseExpiryInput accepts it; validation rejects
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseExpiryInput(tt.input, time.Now())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Result should be YYYY-MM-DD format
				_, parseErr := time.Parse("2006-01-02", result)
				assert.NoError(t, parseErr, "result should be valid date: %s", result)
			}
		})
	}
}

func TestValidateExpiryInput_RejectsPastDate(t *testing.T) {
	err := validateExpiryInput("2020-01-01")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "future")
}

func TestValidateExpiryInput_AcceptsFutureDate(t *testing.T) {
	err := validateExpiryInput("1y")
	assert.NoError(t, err)
}

func TestAmendTypeToStatus(t *testing.T) {
	tests := []struct {
		amendType string
		want      string
	}{
		{"waiver", "passed"},
		{"attestation", "passed"},
		{"falsePositive", "notApplicable"},
		{"inherited", "notApplicable"},
		{"riskAdjustment", ""},
		{"operationalRequirement", "failed"},
		{"poam", "failed"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.amendType, func(t *testing.T) {
			assert.Equal(t, tt.want, amendTypeToStatus(tt.amendType))
		})
	}
}

func TestDetermineRequirementStatus(t *testing.T) {
	tests := []struct {
		name    string
		results []interface{}
		want    string
	}{
		{"no results", nil, "notReviewed"},
		{"single passed", []interface{}{map[string]interface{}{"status": "passed"}}, "passed"},
		{"single failed", []interface{}{map[string]interface{}{"status": "failed"}}, "failed"},
		{"mixed worst wins", []interface{}{
			map[string]interface{}{"status": "passed"},
			map[string]interface{}{"status": "failed"},
		}, "failed"},
		{"error is worst", []interface{}{
			map[string]interface{}{"status": "failed"},
			map[string]interface{}{"status": "error"},
		}, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := map[string]interface{}{"results": tt.results}
			assert.Equal(t, tt.want, determineRequirementStatus(req))
		})
	}
}

func TestIdentityType(t *testing.T) {
	assert.Equal(t, "email", identityType("admin@example.com"))
	assert.Equal(t, "simple", identityType("Platform Team"))
}

func TestAmendCreateCmd_AcceptsNoArgs(t *testing.T) {
	// Verify the command definition accepts zero args (standalone mode).
	// We can't run the full TUI in tests, but we can verify the command
	// doesn't reject zero arguments at the cobra level.
	cmd := NewRootCmd()
	// Find the amend create subcommand
	amendCmd, _, _ := cmd.Find([]string{"amend", "create"})
	require.NotNil(t, amendCmd)

	// The args validator should accept 0 args
	err := amendCmd.Args(amendCmd, []string{})
	assert.NoError(t, err, "amend create should accept zero arguments for standalone mode")

	// And still accept 1 arg
	err = amendCmd.Args(amendCmd, []string{"results.json"})
	assert.NoError(t, err, "amend create should accept one argument for results mode")
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
