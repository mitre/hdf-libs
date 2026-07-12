package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeEvidenceArtifact writes a fake external-evidence corpus and returns its path.
func writeEvidenceArtifact(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corpus.ndjson")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func readEvidenceExternal(t *testing.T, pkgPath string) []interface{} {
	t.Helper()
	data, err := os.ReadFile(pkgPath)
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	ext, _ := doc["externalEvidence"].([]interface{})
	return ext
}

func TestEvidenceAddEvidence_LocalFileComputesChecksum(t *testing.T) {
	pkg := writeTestEvidence(t)
	body := `{"@timestamp":"2026-01-01T00:00:00Z","message":"hello"}` + "\n"
	artifact := writeEvidenceArtifact(t, body)

	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", artifact, "--format", "ecs")
	require.NoError(t, err)

	ext := readEvidenceExternal(t, pkg)
	require.Len(t, ext, 1)
	entry := ext[0].(map[string]interface{})
	assert.Equal(t, "ecs", entry["format"])

	sum := sha256.Sum256([]byte(body))
	checksum := entry["checksum"].(map[string]interface{})
	assert.Equal(t, "sha256", checksum["algorithm"])
	assert.Equal(t, hex.EncodeToString(sum[:]), checksum["value"])
}

func TestEvidenceAddEvidence_URLOmitsChecksum(t *testing.T) {
	pkg := writeTestEvidence(t)

	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "https://evidence.agency.gov/logs/q1.ndjson", "--format", "ocsf")
	require.NoError(t, err)

	ext := readEvidenceExternal(t, pkg)
	require.Len(t, ext, 1)
	entry := ext[0].(map[string]interface{})
	assert.Equal(t, "ocsf", entry["format"])
	_, hasChecksum := entry["checksum"]
	assert.False(t, hasChecksum, "URL input should not auto-compute a checksum")
}

func TestEvidenceAddEvidence_SuppliedChecksum(t *testing.T) {
	pkg := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "s3://lake/ocsf/q1/", "--format", "ocsf",
		"--checksum", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.NoError(t, err)

	entry := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
	checksum := entry["checksum"].(map[string]interface{})
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", checksum["value"])
}

func TestEvidenceAddEvidence_RejectsInvalidChecksum(t *testing.T) {
	for _, bad := range []string{"abc", "nothex-nothex-nothex", "e3b0c44298fc1c14"} { // non-hex or wrong length
		pkg := writeTestEvidence(t)
		_, _, err := executeCommand("evidence", "add-evidence", pkg,
			"--uri", "s3://lake/q1/", "--format", "ocsf", "--checksum", bad)
		require.Error(t, err, "checksum %q should be rejected", bad)
		assert.Contains(t, err.Error(), "SHA-256")
	}
}

func TestEvidenceAddEvidence_NormalizesChecksumCase(t *testing.T) {
	pkg := writeTestEvidence(t)
	upper := "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "s3://lake/q1/", "--format", "ocsf", "--checksum", upper)
	require.NoError(t, err)

	entry := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
	checksum := entry["checksum"].(map[string]interface{})
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", checksum["value"])
}

func TestEvidenceAddEvidence_ReservedFormats(t *testing.T) {
	for _, format := range []string{"ecs", "ocsf", "cyclonedx", "spdx", "raw-log"} {
		pkg := writeTestEvidence(t)
		_, _, err := executeCommand("evidence", "add-evidence", pkg,
			"--uri", "https://x/y", "--format", format)
		require.NoError(t, err, "format %q should be accepted", format)
	}
}

func TestEvidenceAddEvidence_XCustomFormat(t *testing.T) {
	pkg := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "siem-export.json", "--format", "x-splunk-export")
	require.NoError(t, err)
}

func TestEvidenceAddEvidence_RejectsInvalidFormat(t *testing.T) {
	// Query-time models (splunk-cim/ms-asim) and deferred schema-one are not reserved.
	for _, format := range []string{"splunk-cim", "ms-asim", "schema-one", "bogus"} {
		pkg := writeTestEvidence(t)
		_, _, err := executeCommand("evidence", "add-evidence", pkg,
			"--uri", "https://x/y", "--format", format)
		require.Error(t, err, "format %q should be rejected", format)
		// rejected at the command boundary with a clear message, not only by
		// post-serialize schema validation
		assert.Contains(t, err.Error(), "is not valid", "format %q rejected at boundary", format)
	}
}

func TestValidateEvidenceFormat(t *testing.T) {
	for _, ok := range []string{"ecs", "ocsf", "cyclonedx", "spdx", "raw-log", "x-splunk-export", "x-foo", "x-a1-b2"} {
		assert.NoError(t, validateEvidenceFormat(ok), "%q should be valid", ok)
	}
	// uppercase, bare x-, trailing/leading hyphen, non-x custom, empty
	for _, bad := range []string{"X-Splunk", "x-", "x-Foo", "x-foo-", "-x-foo", "splunk-cim", "schema-one", "ECS", ""} {
		assert.Error(t, validateEvidenceFormat(bad), "%q should be rejected", bad)
	}
}

func TestEvidenceAddEvidence_RequiresUriAndFormat(t *testing.T) {
	pkg := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--format", "ecs")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uri")

	pkg2 := writeTestEvidence(t)
	_, _, err = executeCommand("evidence", "add-evidence", pkg2, "--uri", "https://x/y")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestEvidenceAddEvidence_Metadata(t *testing.T) {
	pkg := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "https://x/y", "--format", "ecs",
		"--media-type", "application/x-ndjson", "--format-version", "9.4.0",
		"--collector", "elastic-agent", "--record-count", "4200000",
		"--time-start", "2026-01-01T00:00:00Z", "--time-end", "2026-03-31T23:59:59Z",
		"--description", "Q1 portal logs")
	require.NoError(t, err)

	entry := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
	assert.Equal(t, "application/x-ndjson", entry["mediaType"])
	assert.Equal(t, "9.4.0", entry["formatVersion"])
	assert.Equal(t, "Q1 portal logs", entry["description"])
	meta := entry["metadata"].(map[string]interface{})
	assert.Equal(t, "elastic-agent", meta["collector"])
	assert.EqualValues(t, 4200000, meta["recordCount"])
	tr := meta["timeRange"].(map[string]interface{})
	assert.Equal(t, "2026-01-01T00:00:00Z", tr["start"])
	assert.Equal(t, "2026-03-31T23:59:59Z", tr["end"])
}

func TestEvidenceAddEvidence_Appends(t *testing.T) {
	pkg := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", "a", "--format", "ecs")
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--uri", "b", "--format", "ocsf")
	require.NoError(t, err)
	assert.Len(t, readEvidenceExternal(t, pkg), 2)
}

func TestEvidenceAddEvidence_RejectsNonEvidenceDoc(t *testing.T) {
	// A results document is not an evidence package.
	path := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"passthrough":{},"platform":{}}`), 0o600))

	_, _, err := executeCommand("evidence", "add-evidence", path, "--uri", "x", "--format", "ecs")
	require.Error(t, err)
}

func TestEvidenceInfo_ShowsExternalEvidence(t *testing.T) {
	pkg := writeTestEvidence(t)
	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "https://evidence.agency.gov/logs/q1.ndjson", "--format", "ecs")
	require.NoError(t, err)

	stdout, _, err := executeCommand("evidence", "info", pkg)
	require.NoError(t, err)
	assert.Contains(t, stdout, "External Evidence")
	assert.Contains(t, stdout, "ecs")
	assert.Contains(t, stdout, "q1.ndjson")
}

func TestExternalEvidenceFormatConstraints_DerivedFromSchema(t *testing.T) {
	// Proves the boundary validation reads the schema's External_Evidence_Format
	// (single source of truth), not a hardcoded Go copy — so it cannot drift.
	reserved, pattern, err := externalEvidenceFormatConstraints()
	require.NoError(t, err)
	assert.Equal(t, []string{"ecs", "ocsf", "cyclonedx", "spdx", "raw-log"}, reserved)
	require.NotNil(t, pattern)
	assert.True(t, pattern.MatchString("x-splunk-export"))
	assert.False(t, pattern.MatchString("X-Splunk"))
}
