package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
    "expiresAt": "2099-12-31T00:00:00Z"
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
		// The root application-chain field, not the override-level chain link.
		assert.Contains(t, stdout, "preAmendmentChecksum")
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
		require.Error(t, err)
		assert.Regexp(t, `Expired:\s+1`, stdout)
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
		require.Error(t, err)
		assert.Contains(t, stdout, "NONEXISTENT-99")
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
	doc, err := buildAmendmentsFromOverrides(overrides)
	require.NoError(t, err)

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
		{"operationalRequirement", ""},
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
		{"passed beats notReviewed (canonical ordering)", []interface{}{
			map[string]interface{}{"status": "passed"},
			map[string]interface{}{"status": "notReviewed"},
		}, "passed"},
		{"notApplicable beats notReviewed", []interface{}{
			map[string]interface{}{"status": "notReviewed"},
			map[string]interface{}{"status": "notApplicable"},
		}, "notApplicable"},
		{"unknown statuses ignored", []interface{}{
			map[string]interface{}{"status": "bogus"},
			map[string]interface{}{"status": "passed"},
		}, "passed"},
		{"only unknown statuses roll to notReviewed", []interface{}{
			map[string]interface{}{"status": "bogus"},
		}, "notReviewed"},
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

// writeChainedAmendments writes an amendments file whose overrides are linked
// by previousChecksum, the way `hdf amend create` emits them.
func writeChainedAmendments(t *testing.T, dir, name string, reasons ...string) string {
	t.Helper()
	overrides := make([]map[string]interface{}, 0, len(reasons))
	prev := ""
	for i, reason := range reasons {
		ov := map[string]interface{}{
			"type":          "waiver",
			"requirementId": fmt.Sprintf("AC-%d", i+1),
			"status":        "passed",
			"reason":        reason,
			"appliedBy":     map[string]interface{}{"type": "email", "identifier": "admin@example.com"},
			"appliedAt":     "2026-03-01T00:00:00Z",
			"expiresAt":     "2099-12-31T00:00:00Z",
		}
		if prev != "" {
			ov["previousChecksum"] = map[string]interface{}{"algorithm": "sha256", "value": prev}
		}
		prev = amend.ChecksumOverride(ov)
		overrides = append(overrides, ov)
	}
	raw, err := json.Marshal(map[string]interface{}{"name": "chained", "overrides": overrides})
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func TestAmendVerifyExitStatus(t *testing.T) {
	t.Run("all-valid file exits zero", func(t *testing.T) {
		dir := t.TempDir()
		path := writeChainedAmendments(t, dir, "valid.json", "first reason", "second reason")

		stdout, _, err := executeCommand("amend", "verify", path)
		require.NoError(t, err)
		assert.Contains(t, stdout, "All amendments are valid")
	})

	t.Run("expired amendment exits non-zero with no flag required", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "expired.json")
		doc := `{
			"name": "expired",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "lapsed",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2020-01-01T00:00:00Z",
				"expiresAt": "2020-06-30T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		_, _, err := executeCommand("amend", "verify", path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("tampered amendment exits non-zero", func(t *testing.T) {
		dir := t.TempDir()
		path := writeChainedAmendments(t, dir, "chained.json", "first reason", "second reason", "third reason")

		raw, readErr := os.ReadFile(path) //nolint:gosec // test-controlled path
		require.NoError(t, readErr)
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &doc))
		second := doc["overrides"].([]interface{})[1].(map[string]interface{})
		second["reason"] = "TAMPERED - actually we just wanted it gone"
		tampered, marshalErr := json.Marshal(doc)
		require.NoError(t, marshalErr)
		tamperedPath := filepath.Join(dir, "tampered.json")
		require.NoError(t, os.WriteFile(tamperedPath, tampered, 0o600))

		stdout, _, err := executeCommand("amend", "verify", tamperedPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chain")
		assert.Contains(t, stdout, "AC-3")
	})

	t.Run("structurally invalid amendment exits non-zero", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "malformed.json")
		doc := `{
			"name": "malformed",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		stdout, _, err := executeCommand("amend", "verify", path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
		assert.Contains(t, stdout, "reason is required")
	})

	// Expired and invalid have different remedies (renew the review vs fix the
	// document), so the summary must not collapse them into one number.
	t.Run("summary distinguishes expired from invalid", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "mixed.json")
		doc := `{
			"name": "mixed",
			"overrides": [
				{
					"type": "waiver",
					"requirementId": "AC-1",
					"status": "passed",
					"reason": "lapsed",
					"appliedBy": {"type": "email", "identifier": "admin@example.com"},
					"appliedAt": "2020-01-01T00:00:00Z",
					"expiresAt": "2020-06-30T00:00:00Z"
				},
				{
					"type": "waiver",
					"requirementId": "AC-2",
					"status": "passed",
					"appliedBy": {"type": "email", "identifier": "admin@example.com"},
					"appliedAt": "2026-03-01T00:00:00Z",
					"expiresAt": "2099-12-31T00:00:00Z"
				}
			]
		}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		stdout, _, err := executeCommand("amend", "verify", path)
		require.Error(t, err)
		assert.Regexp(t, `Expired:\s+1`, stdout)
		assert.Regexp(t, `Invalid:\s+1`, stdout)
	})

	// The ruling on this command is that an expired amendment is a failure, not
	// a warning: no flag may opt back into the old green. Asserting on the flag
	// set is not enough — inspecting a parentless cobra command shows an empty
	// set because root's persistent flags are not attached, which is how --json
	// bypassed the exit code undetected. Execute every flag instead.
	t.Run("no flag tolerates an expired amendment", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "expired.json")
		doc := `{
			"name": "expired",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "lapsed",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2020-01-01T00:00:00Z",
				"expiresAt": "2020-06-30T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		resultsPath := filepath.Join(dir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(testResults), 0o600))

		for _, args := range [][]string{
			{"amend", "verify", path},
			{"amend", "verify", "--json", path},
			{"amend", "verify", path, resultsPath},
			{"amend", "verify", "--json", path, resultsPath},
			{"amend", "verify", "--no-headers", path},
			{"amend", "verify", "--debug", path},
		} {
			_, _, err := executeCommand(args...)
			require.Errorf(t, err, "expired amendment passed under %v", args)
			require.Containsf(t, err.Error(), "verification failed",
				"under %v the error was not a verification verdict: %v", args, err)
		}
	})

	// The JSON body reported the failure while the process exited 0, so anything
	// piping to jq saw a green step. The verdict belongs in the exit code on
	// both paths.
	t.Run("json output does not bypass the exit code", func(t *testing.T) {
		dir := t.TempDir()
		path := writeChainedAmendments(t, dir, "chained.json", "first reason", "second reason", "third reason")

		raw, readErr := os.ReadFile(path) //nolint:gosec // test-controlled path
		require.NoError(t, readErr)
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &doc))
		doc["overrides"].([]interface{})[1].(map[string]interface{})["reason"] = "TAMPERED"
		tampered, marshalErr := json.Marshal(doc)
		require.NoError(t, marshalErr)
		tamperedPath := filepath.Join(dir, "tampered.json")
		require.NoError(t, os.WriteFile(tamperedPath, tampered, 0o600))

		stdout, _, err := executeCommand("amend", "verify", "--json", tamperedPath)
		require.Error(t, err)

		// The body must still be parseable JSON carrying the verdict.
		var result amend.VerifyResult
		require.NoError(t, json.Unmarshal([]byte(stdout), &result))
		assert.False(t, result.Chain.Valid)
		assert.True(t, result.HasErrors)
	})

	t.Run("json output carries the chain and invalid counts", func(t *testing.T) {
		dir := t.TempDir()
		path := writeChainedAmendments(t, dir, "valid.json", "first reason", "second reason")

		stdout, _, err := executeCommand("amend", "verify", "--json", path)
		require.NoError(t, err)

		var result amend.VerifyResult
		require.NoError(t, json.Unmarshal([]byte(stdout), &result))
		assert.Equal(t, 2, result.TotalOverrides)
		assert.Equal(t, 2, result.ValidOverrides)
		assert.Equal(t, 0, result.InvalidCount)
		assert.True(t, result.Chain.Established)
		assert.True(t, result.Chain.Valid)
	})
}

func TestAmendApplyRefusesUnverified(t *testing.T) {
	setup := func(t *testing.T) (string, string) {
		t.Helper()
		dir := t.TempDir()
		resultsPath := filepath.Join(dir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(testResults), 0o600))
		return dir, resultsPath
	}

	t.Run("expired amendments are refused, not applied", func(t *testing.T) {
		dir, resultsPath := setup(t)
		path := filepath.Join(dir, "expired.json")
		doc := `{
			"name": "expired",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "lapsed",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2020-01-01T00:00:00Z",
				"expiresAt": "2020-06-30T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		outPath := filepath.Join(dir, "out.json")
		err := runAmendApply(nil, resultsPath, path, outPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
		assert.NoFileExists(t, outPath, "a refused apply must not write output")
	})

	t.Run("a broken chain is refused", func(t *testing.T) {
		dir, resultsPath := setup(t)
		path := writeChainedAmendments(t, dir, "chained.json", "first reason", "second reason")

		raw, readErr := os.ReadFile(path) //nolint:gosec // test-controlled path
		require.NoError(t, readErr)
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &doc))
		doc["overrides"].([]interface{})[0].(map[string]interface{})["reason"] = "TAMPERED"
		tampered, marshalErr := json.Marshal(doc)
		require.NoError(t, marshalErr)
		tamperedPath := filepath.Join(dir, "tampered.json")
		require.NoError(t, os.WriteFile(tamperedPath, tampered, 0o600))

		err := runAmendApply(nil, resultsPath, tamperedPath, filepath.Join(dir, "out.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chain")
	})

	t.Run("a structurally invalid document is refused", func(t *testing.T) {
		dir, resultsPath := setup(t)
		path := filepath.Join(dir, "malformed.json")
		doc := `{
			"name": "malformed",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		err := runAmendApply(nil, resultsPath, path, filepath.Join(dir, "out.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	// Apply and verify must never disagree about the same file.
	t.Run("apply accepts exactly what verify accepts", func(t *testing.T) {
		dir, resultsPath := setup(t)
		path := filepath.Join(dir, "valid.json")
		doc := `{
			"name": "valid",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "risk accepted",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		_, _, verifyErr := executeCommand("amend", "verify", path)
		require.NoError(t, verifyErr)

		outPath := filepath.Join(dir, "out.json")
		require.NoError(t, runAmendApply(nil, resultsPath, path, outPath))
		assert.FileExists(t, outPath)
	})
}

// The amendments-side results link was retired: nothing wrote the field, and
// one amendments document may be applied to many results files, so it cannot
// hold a single results hash. What remains is the assertion that its presence
// changes nothing.
func TestAmendVerifyIgnoresAmendmentsSideResultsLink(t *testing.T) {
	writeResults := func(t *testing.T, dir string) string {
		t.Helper()
		p := filepath.Join(dir, "results.json")
		require.NoError(t, os.WriteFile(p, []byte(testResults), 0o600))
		return p
	}

	// The amendments-side results link is retired: one amendments document may
	// be applied to many results files, so it cannot carry a single results
	// hash, and nothing ever wrote the field. Verify must not report a verdict
	// on it either way.
	t.Run("no results-link verdict is reported, even when the field is present", func(t *testing.T) {
		dir := t.TempDir()
		resultsPath := writeResults(t, dir)
		sum := sha256.Sum256([]byte(testResults))

		amendPath := filepath.Join(dir, "amend.json")
		doc := fmt.Sprintf(`{
			"name": "linked",
			"previousChecksum": {"algorithm": "sha256", "value": %q},
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "risk accepted",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`, hex.EncodeToString(sum[:]))
		require.NoError(t, os.WriteFile(amendPath, []byte(doc), 0o600))

		stdout, _, err := executeCommand("amend", "verify", amendPath, resultsPath)
		require.NoError(t, err)
		// Assert the command actually ran, so the absence below is meaningful.
		assert.Contains(t, stdout, "All checks passed.")
		assert.NotContains(t, stdout, "Results link")
	})
}

// requirementIds and schema-error text come straight out of an untrusted
// document and land in a refusal message on the terminal, so every path that
// renders them must strip escape sequences.
func TestAmendUntrustedTextIsSanitized(t *testing.T) {
	const esc = "\x1b[31mRED\x1b[0m"

	writeAmendments := func(t *testing.T, dir, name, reqID string) string {
		t.Helper()
		overrides := []map[string]interface{}{
			{
				"type": "waiver", "requirementId": reqID, "status": "passed",
				"reason":    "first",
				"appliedBy": map[string]interface{}{"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z",
			},
		}
		second := map[string]interface{}{
			"type": "waiver", "requirementId": reqID + "-2", "status": "passed",
			"reason":    "second",
			"appliedBy": map[string]interface{}{"type": "email", "identifier": "admin@example.com"},
			"appliedAt": "2026-03-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z",
			"previousChecksum": map[string]interface{}{
				"algorithm": "sha256", "value": amend.ChecksumOverride(overrides[0]),
			},
		}
		// Break the chain so the refusal has to name the offending override.
		overrides[0]["reason"] = "TAMPERED"
		raw, err := json.Marshal(map[string]interface{}{
			"name": "esc", "overrides": []interface{}{overrides[0], second},
		})
		require.NoError(t, err)
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, raw, 0o600))
		return path
	}

	t.Run("apply refusal strips escape sequences", func(t *testing.T) {
		dir := t.TempDir()
		resultsPath := filepath.Join(dir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(testResults), 0o600))
		amendPath := writeAmendments(t, dir, "esc.json", "AC-"+esc)

		err := runAmendApply(nil, resultsPath, amendPath, filepath.Join(dir, "out.json"))
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "\x1b", "refusal must not carry escape sequences")
		assert.Contains(t, err.Error(), "RED", "the identifier itself is still reported")
	})

	// The chain-break line is where an attacker-controlled requirementId reaches
	// the terminal, so assert it is BOTH present and stripped — a test that only
	// checks for absence of ESC would pass on empty output.
	t.Run("verify summary strips escape sequences from the chain break", func(t *testing.T) {
		dir := t.TempDir()
		amendPath := writeAmendments(t, dir, "esc.json", "AC-"+esc)

		stdout, _, err := executeCommand("amend", "verify", amendPath)
		require.Error(t, err)
		assert.Contains(t, stdout, "previousChecksum does not match")
		assert.Contains(t, stdout, "RED", "the identifier is still reported, just defanged")
		assert.NotContains(t, stdout, "\x1b")
	})

	// The schema-error line carries document-controlled text: `labels` is an open
	// key space (additionalProperties: {type: string}), so a bad label KEY lands
	// in the error path verbatim. An earlier version of this test used an enum
	// violation, where the message quotes only schema-derived values, and so
	// could never fail.
	t.Run("schema error paths are stripped", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "labels.json")
		doc := `{"name":"n","labels":{"evil\u001b[31mRED\u001b[0mkey":123},` +
			`"overrides":[{"type":"waiver","requirementId":"AC-1","status":"passed","reason":"r",` +
			`"appliedBy":{"type":"email","identifier":"admin@example.com"},` +
			`"appliedAt":"2026-03-01T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z"}]}`
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

		stdout, _, err := executeCommand("amend", "verify", path)
		require.Error(t, err)
		assert.Contains(t, stdout, "Invalid type", "the schema error must still be reported")
		assert.Contains(t, stdout, "RED", "the offending key is still named, just defanged")
		assert.NotContains(t, stdout, "\x1b")
	})

	t.Run("missing requirement ids are stripped", func(t *testing.T) {
		dir := t.TempDir()
		resultsPath := filepath.Join(dir, "results.json")
		require.NoError(t, os.WriteFile(resultsPath, []byte(testResults), 0o600))

		amendPath := filepath.Join(dir, "missing.json")
		doc := map[string]interface{}{
			"name": "missing",
			"overrides": []interface{}{map[string]interface{}{
				"type": "waiver", "requirementId": "NOPE-" + esc, "status": "passed",
				"reason":    "unmatched",
				"appliedBy": map[string]interface{}{"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z",
			}},
		}
		raw, err := json.Marshal(doc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(amendPath, raw, 0o600))

		stdout, _, cmdErr := executeCommand("amend", "verify", amendPath, resultsPath)
		require.Error(t, cmdErr)
		assert.NotContains(t, stdout, "\x1b")
		assert.Contains(t, stdout, "Missing requirements:")
	})
}
