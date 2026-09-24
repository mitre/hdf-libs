//nolint:dupl
package cmd

import (
	"encoding/json"
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

// writeVerifyPackage drops a package and its documents into a temp tree and
// returns the package path. Content refs are written verbatim so a test can put
// a deliberately-bad one in.
func writeVerifyPackage(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rhel9-results.json"), src, 0o600))
	pkg := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkg, []byte(body), 0o600))
	return pkg
}

// An absolute content ref used to be re-rooted under the package directory:
// "/etc/passwd" silently became "<pkgdir>/etc/passwd", so verify reported on a
// different file than the reference named. Refusing is the only honest outcome —
// a content reference is relative to the package by definition.
func TestEvidenceVerify_RejectsAbsoluteContentURI(t *testing.T) {
	pkg := writeVerifyPackage(t, `{
		"name": "Absolute Ref Package",
		"contents": [{"type": "hdf-results", "uri": "/etc/passwd"}]
	}`)

	_, _, err := executeCommand("evidence", "verify", pkg)
	require.Error(t, err, "an absolute content reference must be refused, not re-rooted")
	assert.Contains(t, err.Error(), "relative",
		"the message must say content references are package-relative")
}

// A URL-shaped content ref became a local path with a "https:" component and
// failed as file-not-found. The schema's contents[] carries documents bundled
// with the package; remote artifacts belong in externalEvidence.
func TestEvidenceVerify_RejectsRemoteContentURI(t *testing.T) {
	pkg := writeVerifyPackage(t, `{
		"name": "Remote Ref Package",
		"contents": [{"type": "hdf-results", "uri": "https://example.com/results.json"}]
	}`)

	_, _, err := executeCommand("evidence", "verify", pkg)
	require.Error(t, err, "a remote content reference must be refused")
	assert.Contains(t, err.Error(), "externalEvidence",
		"the message must point at externalEvidence as the place for remote artifacts")
}

// The boundary: the refusal above covers contents[] ONLY. A package may carry
// externalEvidence with absolute or remote URIs, and a bundled document may carry
// its own externalReferences as bare URIs — both are correct and common, and
// neither is ever resolved or downloaded. An over-broad check here would reject
// packages that are valid today.
func TestEvidenceVerify_AllowsRemoteExternalEvidenceAndDocumentRefs(t *testing.T) {
	dir := t.TempDir()

	// A real results document, given its own externalReferences with a bare URI.
	src, err := os.ReadFile(filepath.Join(evidenceFixtureDir, "rhel9-results.json"))
	require.NoError(t, err)
	var results map[string]interface{}
	require.NoError(t, json.Unmarshal(src, &results))
	results["externalReferences"] = []interface{}{
		map[string]interface{}{
			"sourceName": "cve",
			"externalId": "CVE-2021-44228",
			"href":       "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
		},
	}
	withRefs, err := json.Marshal(results)
	require.NoError(t, err)
	resultsPath := filepath.Join(dir, "rhel9-results.json")
	require.NoError(t, os.WriteFile(resultsPath, withRefs, 0o600))

	pkg := filepath.Join(dir, "pkg.json")
	require.NoError(t, os.WriteFile(pkg, []byte(`{
		"name": "Remote External Evidence Package",
		"contents": [{"type": "hdf-results", "uri": "rhel9-results.json"}],
		"externalEvidence": [
			{"uri": "https://logs.example.com/corpus.ndjson", "format": "ecs"},
			{"uri": "/mnt/archive/threat-intel.json", "format": "x-stix"}
		]
	}`), 0o600))

	_, _, verifyErr := executeCommand("evidence", "verify", pkg, "--checksums-only")
	require.NoError(t, verifyErr,
		"remote externalEvidence and a document's own externalReferences must not be refused")
}

// Traversal was already refused by SafePath; the new checks must not weaken it.
func TestEvidenceVerify_StillRefusesTraversal(t *testing.T) {
	pkg := writeVerifyPackage(t, `{
		"name": "Traversal Package",
		"contents": [{"type": "hdf-results", "uri": "../escape.json"}]
	}`)

	_, _, err := executeCommand("evidence", "verify", pkg)
	require.Error(t, err, "a traversing content reference must stay refused")
}
