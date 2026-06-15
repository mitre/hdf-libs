package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// richResults is a fixture with multiple targets (FQDN, IP, neither) and
// multiple baselines with various requirement statuses for full branch coverage.
const richResults = `{
  "baselines": [
    {
      "name": "baseline-a",
      "title": "Baseline Alpha",
      "version": "1.0",
      "status": "loaded",
      "checksum": {"algorithm": "sha256", "value": "aaa"},
      "depends": [],
      "groups": [],
      "inspecVersion": "5.0.0",
      "supports": [],
      "requirements": [
        {
          "id": "AC-1", "impact": 0.7, "title": "Access Control Policy",
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "failed", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 1, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        },
        {
          "id": "AC-2", "impact": 0.5,
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "passed", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 2, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        },
        {
          "id": "AC-3", "impact": 0.0,
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "notApplicable", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 3, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        },
        {
          "id": "AC-4", "impact": 0.9,
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "error", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 4, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        }
      ]
    },
    {
      "name": "baseline-b",
      "checksum": {"algorithm": "sha256", "value": "bbb"},
      "depends": [],
      "groups": [],
      "inspecVersion": "5.0.0",
      "supports": [],
      "requirements": [
        {
          "id": "CM-1", "impact": 0.5,
          "descriptions": [{"label": "default", "data": "test"}],
          "results": [{"status": "passed", "codeDesc": "x", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
          "tags": {}, "code": "", "refs": [],
          "sourceLocation": {"line": 1, "ref": "test.rb"},
          "statusOverrides": [], "evidence": [], "poams": []
        }
      ]
    }
  ],
  "components": [
    {"type": "host", "name": "web-server", "fqdn": "web.example.com"},
    {"type": "host", "name": "db-server", "ipAddress": "10.0.0.5"},
    {"type": "application", "name": "portal-app"}
  ],
  "statistics": {"duration": 1.5}
}`

func writeRichFixture(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "rich-results.json")
	require.NoError(t, os.WriteFile(path, []byte(richResults), 0o600))
	return path
}

func TestListSummary(t *testing.T) {
	fixture := writeRichFixture(t)

	t.Run("human summary shows counts and status breakdown", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Baselines:    2")
		assert.Contains(t, stdout, "Requirements: 5")
		assert.Contains(t, stdout, "Components:   3")
		assert.Contains(t, stdout, "passed")
		assert.Contains(t, stdout, "failed")
		assert.Contains(t, stdout, "error")
		assert.Contains(t, stdout, "not_applicable")
	})

	t.Run("JSON summary includes all fields", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture, "--json")
		require.NoError(t, err)

		var summary map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &summary))
		assert.Equal(t, float64(2), summary["baselines"])
		assert.Equal(t, float64(5), summary["requirements"])
		assert.Equal(t, float64(3), summary["components"])
		assert.Equal(t, float64(2), summary["passed"])
		assert.Equal(t, float64(1), summary["failed"])
		assert.Equal(t, float64(1), summary["error"])
		assert.Equal(t, float64(1), summary["not_applicable"])
	})
}

func TestListComponentsDetail(t *testing.T) {
	fixture := writeRichFixture(t)

	t.Run("human output shows target details with FQDN and IP", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture, "--detail", "components")
		require.NoError(t, err)
		assert.Contains(t, stdout, "Components: 3")
		assert.Contains(t, stdout, "web-server")
		assert.Contains(t, stdout, "web.example.com")
		assert.Contains(t, stdout, "db-server")
		assert.Contains(t, stdout, "10.0.0.5")
		assert.Contains(t, stdout, "portal-app")
	})

	t.Run("JSON output includes FQDN and IP", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture, "--detail", "components", "--json")
		require.NoError(t, err)

		var targets []map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stdout), &targets))
		require.Len(t, targets, 3)

		assert.Equal(t, "web.example.com", targets[0]["fqdn"])
		assert.Equal(t, "10.0.0.5", targets[1]["ip_address"])
		// Third target has neither FQDN nor IP — fields should be omitted
		_, hasFQDN := targets[2]["fqdn"]
		_, hasIP := targets[2]["ip_address"]
		assert.False(t, hasFQDN)
		assert.False(t, hasIP)
	})
}

func TestListComponentsEmpty(t *testing.T) {
	// Create fixture with no targets
	noTargets := `{"baselines": [{"name": "b", "checksum": {"algorithm": "sha256", "value": "x"}, "depends": [], "groups": [], "inspecVersion": "5", "supports": [], "requirements": [{"id": "SV-1", "impact": 0.5, "tags": {}, "descriptions": [{"label": "default", "data": "Test"}], "results": [{"status": "passed", "codeDesc": "Test", "startTime": "2025-01-01T00:00:00Z"}]}]}], "statistics": {"duration": 0}}`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "no-targets.json")
	require.NoError(t, os.WriteFile(path, []byte(noTargets), 0o600))

	t.Run("human output says no targets", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "components")
		require.NoError(t, err)
		assert.Contains(t, stdout, "No components defined")
	})

	t.Run("JSON output returns empty array", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "components", "--json")
		require.NoError(t, err)
		assert.Contains(t, stdout, "[]")
	})
}

func TestListRequirementsAllFlag(t *testing.T) {
	fixture := writeRichFixture(t)

	t.Run("--all shows flat list with status symbols", func(t *testing.T) {
		stdout, _, err := executeCommand("list", fixture, "--detail", "requirements", "--all")
		require.NoError(t, err)
		// Should use status symbols (✓, ✗, !, ○, ?)
		assert.Contains(t, stdout, "AC-1")
		assert.Contains(t, stdout, "AC-2")
	})
}

func TestListErrorCases(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		_, _, err := executeCommand("list", "/nonexistent/file.json")
		require.Error(t, err)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "bad.json")
		require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))
		_, _, err := executeCommand("list", path)
		require.Error(t, err)
	})
}

func TestListSystemDataFlows(t *testing.T) {
	// componentId / dataFlows.from / dataFlows.to are UUID-formatted per
	// the hdf-system schema; using non-UUID literals fails the input gate.
	const (
		webUUID = "11111111-1111-1111-1111-111111111111"
		dbUUID  = "22222222-2222-2222-2222-222222222222"
	)
	sysJSON := `{
		"name": "Portal-Prod",
		"components": [
			{"name": "WebTier", "type": "application", "componentId": "` + webUUID + `"},
			{"name": "DB", "type": "database", "componentId": "` + dbUUID + `"}
		],
		"dataFlows": [
			{"from": "` + webUUID + `", "to": "` + dbUUID + `", "protocol": "JDBC", "port": 5432, "description": "Web to database"},
			{"from": "` + dbUUID + `", "to": "` + webUUID + `", "protocol": "JDBC", "description": "Query results"}
		]
	}`
	path := filepath.Join(t.TempDir(), "system.json")
	require.NoError(t, os.WriteFile(path, []byte(sysJSON), 0o600))

	t.Run("detail dataFlows shows flows", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "dataFlows")
		require.NoError(t, err)
		assert.Contains(t, stdout, "Data Flows: 2")
		assert.Contains(t, stdout, webUUID)
		assert.Contains(t, stdout, dbUUID)
		assert.Contains(t, stdout, "JDBC")
	})

	t.Run("detail dataFlows JSON output", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "dataFlows", "--json")
		require.NoError(t, err)
		assert.Contains(t, stdout, webUUID)
	})

	t.Run("alias d maps to dataFlows", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "d")
		require.NoError(t, err)
		assert.Contains(t, stdout, "Data Flows: 2")
	})

	t.Run("detail components on system doc", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path, "--detail", "components")
		require.NoError(t, err)
		assert.Contains(t, stdout, "WebTier")
		assert.Contains(t, stdout, "DB")
	})

	t.Run("system summary without detail", func(t *testing.T) {
		stdout, _, err := executeCommand("list", path)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Portal-Prod")
		assert.Contains(t, stdout, "Components")
		assert.Contains(t, stdout, "Data Flows")
	})
}

func TestResolveDetailAlias(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"r", "requirements"},
		{"requirement", "requirements"},
		{"b", "baselines"},
		{"baseline", "baselines"},
		{"t", "components"},
		{"c", "components"},
		{"component", "components"},
		{"g", "groups"},
		{"group", "groups"},
		{"a", "assessments"},
		{"assessment", "assessments"},
		{"o", "amendments"},
		{"override", "amendments"},
		{"d", "dataFlows"},
		{"dataflow", "dataFlows"},
		{"dataflows", "dataFlows"},
		{"p", "baselines"}, // legacy alias
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveDetailAlias(tt.input))
		})
	}
}

func TestTruncateTitle(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short title", "Hello", 50, "Hello"},
		{"exact length", "12345", 5, "12345"},
		{"long title truncated", "This is a very long title that exceeds the max", 20, "This is a very lo..."},
		{"empty title placeholder", "", 50, "(no title)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, truncateTitle(tt.input, tt.maxLen))
		})
	}
}
