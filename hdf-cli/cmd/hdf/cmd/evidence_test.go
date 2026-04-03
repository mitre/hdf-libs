package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const evidenceFixture = `{
  "name": "Q1-2026 Authorization Package",
  "preparedBy": {"identifier": "issm@agency.gov", "type": "email"},
  "preparedAt": "2026-03-15T00:00:00Z",
  "systemRef": "portal-prod.hdf-system.json",
  "contents": [
    {"type": "hdf-system", "uri": "portal-prod.hdf-system.json"},
    {"type": "hdf-baseline", "uri": "rhel9-stig.hdf-baseline.json", "checksum": {"algorithm": "sha256", "value": "abc123"}},
    {"type": "hdf-results", "uri": "scan-2026-03.hdf-results.json", "checksum": {"algorithm": "sha256", "value": "def456"}},
    {"type": "hdf-amendments", "uri": "waivers.hdf-amendments.json"},
    {"type": "hdf-comparison", "uri": "diff-q4-q1.hdf-comparison.json"}
  ],
  "completenessCheck": {
    "allBaselinesAssessed": true,
    "allComponentsCovered": true,
    "expiredWaivers": 0,
    "unresolvedPoams": 2,
    "compliancePercent": 94
  }
}`

func writeEvidenceFixture(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "evidence.json")
	require.NoError(t, os.WriteFile(p, []byte(evidenceFixture), 0o600))
	return p
}

func TestEvidenceInfoCommand(t *testing.T) { //nolint:dupl
	t.Run("displays evidence info in human-readable format", func(t *testing.T) {
		fixture := writeEvidenceFixture(t)
		stdout, _, err := executeCommand("evidence", "info", fixture)
		require.NoError(t, err)

		assert.Contains(t, stdout, "Evidence Package: Q1-2026 Authorization Package")
		assert.Contains(t, stdout, "Prepared by: issm@agency.gov")
		assert.Contains(t, stdout, "Prepared at: 2026-03-15T00:00:00Z")
		assert.Contains(t, stdout, "System: portal-prod.hdf-system.json")
		assert.Contains(t, stdout, "Contents (5):")
		assert.Contains(t, stdout, "hdf-system")
		assert.Contains(t, stdout, "portal-prod.hdf-system.json")
		assert.Contains(t, stdout, "rhel9-stig.hdf-baseline.json")
		assert.Contains(t, stdout, "\u2713 checksum")
		assert.Contains(t, stdout, "waivers.hdf-amendments.json")
		assert.Contains(t, stdout, "Completeness:")
		assert.Contains(t, stdout, "All baselines assessed: yes")
		assert.Contains(t, stdout, "All components covered: yes")
		assert.Contains(t, stdout, "Expired waivers: 0")
		assert.Contains(t, stdout, "Unresolved POA&Ms: 2")
		assert.Contains(t, stdout, "Compliance: 94%")
	})

	t.Run("displays evidence info in JSON format", func(t *testing.T) {
		fixture := writeEvidenceFixture(t)
		stdout, _, err := executeCommand("evidence", "info", "--json", fixture)
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &doc))
		assert.Equal(t, "Q1-2026 Authorization Package", doc["name"])
		assert.Equal(t, "portal-prod.hdf-system.json", doc["systemRef"])
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "info", "/nonexistent/file.json")
		require.Error(t, err)
	})

	t.Run("returns usage error with no args", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "info")
		require.Error(t, err)
	})
}

func TestBoolYesNo(t *testing.T) {
	assert.Equal(t, "yes", boolYesNo(true))
	assert.Equal(t, "no", boolYesNo(false))
}
