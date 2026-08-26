package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const agentOverrideFixture = "testdata/agent-overrides/applied-results.json"
const cleanResultsFixture = "testdata/evidence-verify/rhel9-results.json"

// TestReadout_CountsAgentOverrides is the card's designated first-failing test:
// the agent-attributed override count (appliedBy.type=="agent", the system one
// excluded) is surfaced in the hdf validate, hdf validate threshold, and hdf
// evidence verify readouts.
func TestReadout_CountsAgentOverrides(t *testing.T) {
	t.Run("validate", func(t *testing.T) {
		stdout, stderr, err := executeCommand("validate", agentOverrideFixture)
		if err != nil {
			t.Fatalf("validate failed: %v\n%s", err, stderr)
		}
		if !strings.Contains(stdout+stderr, "Agent-attributed overrides: 1") {
			t.Fatalf("validate readout missing agent-override count:\n%s%s", stdout, stderr)
		}
	})

	t.Run("threshold", func(t *testing.T) {
		// compliance.min: 0 always passes, so the command exits 0 and the readout shows.
		stdout, stderr, err := executeCommand("validate", "threshold", agentOverrideFixture, "-I", "{compliance.min: 0}")
		if err != nil {
			t.Fatalf("threshold failed: %v\n%s", err, stderr)
		}
		if !strings.Contains(stdout+stderr, "Agent-attributed overrides: 1") {
			t.Fatalf("threshold readout missing agent-override count:\n%s%s", stdout, stderr)
		}
	})

	t.Run("evidence verify", func(t *testing.T) {
		pkg := buildEvidencePackage(t, agentOverrideFixture)
		stdout, stderr, _ := executeCommand("evidence", "verify", pkg)
		if !strings.Contains(stdout+stderr, "Agent-attributed overrides: 1") {
			t.Fatalf("evidence verify readout missing agent-override count:\n%s%s", stdout, stderr)
		}
	})
}

// A results file with zero agent-attributed overrides reports 0 cleanly — the
// line is present, not omitted, and there is no crash.
func TestReadout_ZeroAgentOverrides(t *testing.T) {
	stdout, stderr, err := executeCommand("validate", cleanResultsFixture, "--type", "results")
	if err != nil {
		t.Fatalf("validate failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout+stderr, "Agent-attributed overrides: 0") {
		t.Fatalf("a clean results file must still report the count as 0:\n%s%s", stdout, stderr)
	}
}

// The count is a results-only detective surface; validating a non-results
// document must not emit it.
func TestValidateReadout_NonResultsNoCount(t *testing.T) {
	stdout, stderr, err := executeCommand("validate", "testdata/evidence-verify/system.json", "--type", "system")
	if err != nil {
		t.Fatalf("validate failed: %v\n%s", err, stderr)
	}
	if strings.Contains(stdout+stderr, "Agent-attributed overrides") {
		t.Fatalf("a non-results document must not surface the agent-override count:\n%s%s", stdout, stderr)
	}
}

// countAgentOverrides is only called on already-validated results; unparseable
// bytes must degrade to 0, never panic.
func TestCountAgentOverrides_InvalidReturnsZero(t *testing.T) {
	if n := countAgentOverrides([]byte("not valid hdf")); n != 0 {
		t.Fatalf("invalid input should count 0 agent overrides, got %d", n)
	}
}

// buildEvidencePackage writes a temp evidence package (no planRef → checksum-only
// verify) referencing a copy of the given results fixture with a matching
// checksum, and returns the package path.
func buildEvidencePackage(t *testing.T, resultsFixture string) string {
	t.Helper()
	dir := t.TempDir()
	data, err := os.ReadFile(resultsFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "results.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	pkg := fmt.Sprintf(`{
  "name": "Agent-override evidence",
  "contents": [
    {"type": "hdf-results", "uri": "results.json", "checksum": {"algorithm": "sha256", "value": %q}}
  ]
}`, hex.EncodeToString(sum[:]))
	pkgPath := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(pkgPath, []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	return pkgPath
}
