package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A schema-valid v3 results doc carrying the legacy SAF-supplement top-level
// target + passthrough. Before normalization ajv would reject it and the Go
// typed unmarshal would drop the attribution; after the pre-validation
// normalizer (camfd) a command accepts it and warns.
const safSupplementedResults = `{
  "timestamp": "2026-01-01T00:00:00Z",
  "generator": {"name": "t", "version": "0.0.1"},
  "statistics": {"duration": 0.1},
  "baselines": [{
    "name": "B",
    "resultsChecksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"},
    "requirements": [{
      "id": "x", "title": "t", "impact": 0, "tags": {},
      "descriptions": [{"label": "default", "data": "d"}],
      "results": [{"status": "passed", "codeDesc": "d", "startTime": "2026-01-01T00:00:00Z"}]
    }]
  }],
  "target": {"id": "prod-account", "type": "cloudAccount", "boundary": "sparc"},
  "passthrough": {"audit": {"runId": "r-123"}}
}`

// TestQueryAcceptsSAFSupplementedResults is the CLI end-to-end for camfd: a
// SAF-supplemented results file flows through parseHDFResults (used by query),
// is accepted, and the deprecation warning reaches stderr.
func TestQueryAcceptsSAFSupplementedResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saf-results.json")
	require.NoError(t, os.WriteFile(path, []byte(safSupplementedResults), 0o600))

	_, stderr, err := executeCommand("query", path)
	require.NoError(t, err, "a SAF-supplemented results doc must be accepted")
	assert.Contains(t, stderr, "deprecated", "the SAF-supplement deprecation warning must reach stderr")
}

// TestConvertMigratesSAFSupplementedResults is the ADR-0015 / #234 motivating
// path: `hdf convert` on a SAF-supplemented HDF results doc must migrate
// target→a cloudAccount component and passthrough→extensions.passthrough in the
// OUTPUT (not just the parse path), and surface the deprecation warning.
func TestConvertMigratesSAFSupplementedResults(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "saf-results.json")
	out := filepath.Join(dir, "out.json")
	require.NoError(t, os.WriteFile(in, []byte(safSupplementedResults), 0o600))

	// Explicit hdf@3→hdf@3 (identity) so the assertion targets the HDF-input
	// normalization deterministically, without depending on convert's version
	// auto-detection (which is order-sensitive in the full suite — a pre-existing
	// harness fragility unrelated to this change; the bare `--to hdf` form works
	// standalone, verified against the built binary).
	_, stderr, err := executeCommand("convert", in, "--from", "hdf@3", "--to", "hdf@3", "-o", out)
	require.NoError(t, err, "convert must accept a SAF-supplemented HDF results doc")
	assert.Contains(t, stderr, "deprecated", "convert must surface the deprecation warning")

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))

	_, hasTarget := doc["target"]
	_, hasPassthrough := doc["passthrough"]
	assert.False(t, hasTarget, "convert output must not carry the raw top-level target")
	assert.False(t, hasPassthrough, "convert output must not carry the raw top-level passthrough")

	comps, _ := doc["components"].([]any)
	found := false
	for _, c := range comps {
		m, _ := c.(map[string]any)
		if m["name"] == "prod-account" && m["type"] == "cloudAccount" {
			found = true
		}
	}
	assert.True(t, found, "convert output must carry the migrated cloudAccount component")
	ext, _ := doc["extensions"].(map[string]any)
	require.NotNil(t, ext, "convert output must carry extensions")
	assert.Contains(t, ext, "passthrough", "passthrough must be migrated under extensions")
}
