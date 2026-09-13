//nolint:dupl
package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const evidenceFixtureDir = "testdata/evidence-verify"

func TestEvidenceVerify_ChecksumsPass(t *testing.T) {
	_, _, err := executeCommand("evidence", "verify",
		filepath.Join(evidenceFixtureDir, "evidence.json"), "--checksums-only")
	require.NoError(t, err)
}

func TestEvidenceVerify_CompletenessPass(t *testing.T) {
	// Default mode: plan has RHEL9-STIG and PostgreSQL-STIG,
	// evidence package has results for both.
	_, _, err := executeCommand("evidence", "verify",
		filepath.Join(evidenceFixtureDir, "evidence.json"))
	require.NoError(t, err)
}

func TestEvidenceVerify_CompletenessFail(t *testing.T) {
	// Evidence package missing PostgreSQL-STIG results.
	incomplete := `{
		"name": "Incomplete Evidence",
		"planRef": "plan.json",
		"contents": [
			{"type": "hdf-results", "uri": "rhel9-results.json"}
		]
	}`
	// Write to the fixture dir so plan.json and results resolve
	path := filepath.Join(evidenceFixtureDir, "incomplete-evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(incomplete), 0o644))
	t.Cleanup(func() { _ = os.Remove(path) })

	_, _, err := executeCommand("evidence", "verify", path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PostgreSQL-STIG")
}

func TestEvidenceVerify_NoPlanRef(t *testing.T) {
	// Without planRef, verify should warn and fall back to checksums.
	noPlan := `{
		"name": "No Plan Evidence",
		"contents": [
			{"type": "hdf-results", "uri": "rhel9-results.json"}
		]
	}`
	path := filepath.Join(evidenceFixtureDir, "noplan-evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(noPlan), 0o644))
	t.Cleanup(func() { _ = os.Remove(path) })

	_, stderr, err := executeCommand("evidence", "verify", path)
	require.NoError(t, err)
	assert.Contains(t, stderr, "no planRef")
}

// The evidence package is read through the size-gated boundary (readInputFile),
// so --max-size is honored instead of an unbounded os.ReadFile.
func TestEvidenceVerify_RejectsOversizeInput(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "big.json")
	require.NoError(t, os.WriteFile(pkg, make([]byte, 2*1024*1024), 0o600)) // 2 MB
	_, _, err := executeCommand("evidence", "verify", pkg, "--max-size", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

// Files the package REFERENCES go through the same size-gated boundary as the
// package itself — an in-package reference is still untrusted input.
func TestEvidenceVerify_RejectsOversizeReferencedFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big-results.json"), make([]byte, 2*1024*1024), 0o600))
	pkg := `{
		"name": "Oversize Reference",
		"contents": [
			{"type": "hdf-results", "uri": "big-results.json",
			 "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}}
		]
	}`
	path := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(pkg), 0o600))

	_, _, err := executeCommand("evidence", "verify", path, "--checksums-only", "--max-size", "1")
	require.Error(t, err)
	// Gated: the read fails outright (an error), rather than hashing 2 MB into a mismatch.
	assert.Contains(t, err.Error(), "0 checksum mismatches, 1 errors")
}

// The plan a package points at is read through the same boundary.
func TestEvidenceVerify_RejectsOversizePlan(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plan.json"), make([]byte, 2*1024*1024), 0o600))
	pkg := `{
		"name": "Oversize Plan",
		"planRef": "plan.json",
		"contents": [
			{"type": "hdf-results", "uri": "rhel9-results.json"}
		]
	}`
	path := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(pkg), 0o600))

	_, _, err := executeCommand("evidence", "verify", path, "--max-size", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read plan")
	assert.Contains(t, err.Error(), "too large")
}

// Export reads package-referenced documents through the same gated boundary.
func TestEvidenceExport_RejectsOversizeReferencedFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big-results.json"), make([]byte, 2*1024*1024), 0o600))
	pkg := `{
		"name": "Oversize Reference",
		"contents": [
			{"type": "hdf-results", "uri": "big-results.json",
			 "checksum": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}}
		]
	}`
	path := filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(path, []byte(pkg), 0o600))

	_, stderr, err := executeCommand("evidence", "export", path, "-o", filepath.Join(dir, "out"), "--max-size", "1")
	require.NoError(t, err)
	assert.Contains(t, stderr, "could not read")
	assert.Contains(t, stderr, "too large")
}
