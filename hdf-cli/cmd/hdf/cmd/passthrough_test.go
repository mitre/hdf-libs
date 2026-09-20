package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalV3Results is a schema-valid HDF v3 results document used to exercise the
// attribution commands (set must pass the output-validation gate).
const minimalV3Results = `{
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
  }]
}`

func writeV3Results(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "results.json")
	if err := os.WriteFile(p, []byte(minimalV3Results), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func getPassthrough(t *testing.T, path string) map[string]any {
	t.Helper()
	stdout, stderr, err := executeCommand("passthrough", "get", path)
	if err != nil {
		t.Fatalf("passthrough get failed: %v (stderr: %s)", err, stderr)
	}
	var m map[string]any
	if strings.TrimSpace(stdout) == "" {
		return m
	}
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("passthrough get output not JSON: %v (%q)", err, stdout)
	}
	return m
}

// set writes extensions.passthrough; a second set MERGES (sibling key survives),
// and get round-trips — the core attribution-without-saf-cli workflow (#235).
func TestPassthroughSetMergesAndGetRoundTrips(t *testing.T) {
	path := writeV3Results(t)

	if _, stderr, err := executeCommand("passthrough", "set", path, "--data", `{"audit":{"runId":"r1"}}`); err != nil {
		t.Fatalf("passthrough set #1 failed: %v (stderr: %s)", err, stderr)
	}
	pt := getPassthrough(t, path)
	if audit, _ := pt["audit"].(map[string]any); audit["runId"] != "r1" {
		t.Fatalf("first set not round-tripped; got %v", pt)
	}

	// Second writer adds a different top-level key; the first must survive (merge).
	if _, stderr, err := executeCommand("passthrough", "set", path, "--data", `{"oscal":{"blockId":"b2"}}`); err != nil {
		t.Fatalf("passthrough set #2 failed: %v (stderr: %s)", err, stderr)
	}
	pt = getPassthrough(t, path)
	if audit, _ := pt["audit"].(map[string]any); audit["runId"] != "r1" {
		t.Errorf("merge lost the sibling audit key; got %v", pt)
	}
	if oscal, _ := pt["oscal"].(map[string]any); oscal["blockId"] != "b2" {
		t.Errorf("second set not applied; got %v", pt)
	}
}

// --replace overwrites the whole passthrough instead of merging.
func TestPassthroughSetReplace(t *testing.T) {
	path := writeV3Results(t)
	mustRun(t, "passthrough", "set", path, "--data", `{"audit":{"runId":"r1"}}`)
	mustRun(t, "passthrough", "set", path, "--replace", "--data", `{"fresh":true}`)
	pt := getPassthrough(t, path)
	if _, ok := pt["audit"]; ok {
		t.Errorf("--replace should have dropped the prior audit key; got %v", pt)
	}
	if pt["fresh"] != true {
		t.Errorf("--replace did not write the new content; got %v", pt)
	}
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	if _, stderr, err := executeCommand(args...); err != nil {
		t.Fatalf("%v failed: %v (stderr: %s)", args, err, stderr)
	}
}
