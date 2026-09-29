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

// The evidence-package input is read through the size-gated boundary
// (readInputFile), so --max-size is honored instead of an unbounded os.ReadFile.
func TestEvidenceAddEvidence_RejectsOversizeInput(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "big.json")
	require.NoError(t, os.WriteFile(pkg, make([]byte, 2*1024*1024), 0o600)) // 2 MB
	artifact := writeEvidenceArtifact(t, "x")

	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", artifact, "--format", "ecs", "--max-size", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
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

// A pipeline's artifacts directory holds several foreign artifacts at once. One
// invocation per artifact does not scale, and the whole point of the epic is that
// anything HDF can reference is easy to pull in.
func TestEvidenceAddEvidence_AcceptsMultipleURIsInOneInvocation(t *testing.T) {
	pkg := writeTestEvidence(t)
	a := writeEvidenceArtifact(t, `{"@timestamp":"2026-01-01T00:00:00Z","message":"one"}`+"\n")
	b := writeEvidenceArtifact(t, `{"@timestamp":"2026-01-02T00:00:00Z","message":"two"}`+"\n")
	c := writeEvidenceArtifact(t, `{"@timestamp":"2026-01-03T00:00:00Z","message":"three"}`+"\n")

	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", a, "--uri", b, "--uri", c, "--format", "ecs")
	require.NoError(t, err)

	ext := readEvidenceExternal(t, pkg)
	require.Len(t, ext, 3, "each --uri must become its own entry")

	seen := map[string]bool{}
	for _, e := range ext {
		entry := e.(map[string]interface{})
		assert.Equal(t, "ecs", entry["format"], "a single --format applies to every artifact")
		cs := entry["checksum"].(map[string]interface{})
		val := cs["value"].(string)
		assert.Len(t, val, 64)
		assert.False(t, seen[val], "each artifact must be hashed independently, not share a digest")
		seen[val] = true
	}
}

// Different artifacts usually have different formats. --format matched pairwise
// keeps that in one invocation; a count that is neither 1 nor len(--uri) is
// ambiguous and must be refused rather than guessed.
func TestEvidenceAddEvidence_FormatsMatchPairwiseOrRefuse(t *testing.T) {
	pkg := writeTestEvidence(t)
	logs := writeEvidenceArtifact(t, `{"@timestamp":"2026-01-01T00:00:00Z"}`+"\n")
	sbom := writeEvidenceArtifact(t, `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)

	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", logs, "--uri", sbom, "--format", "ecs", "--format", "cyclonedx")
	require.NoError(t, err)

	ext := readEvidenceExternal(t, pkg)
	require.Len(t, ext, 2)
	assert.Equal(t, "ecs", ext[0].(map[string]interface{})["format"])
	assert.Equal(t, "cyclonedx", ext[1].(map[string]interface{})["format"])

	pkg2 := writeTestEvidence(t)
	_, _, err2 := executeCommand("evidence", "add-evidence", pkg2,
		"--uri", logs, "--uri", sbom, "--format", "ecs", "--format", "cyclonedx", "--format", "spdx")
	require.Error(t, err2, "three formats for two artifacts is ambiguous")
	assert.Contains(t, err2.Error(), "--format")
}

// Inference must never be silent. A wrongly-labelled artifact is worse than an
// unlabelled one, because a GRC consumer trusts the discriminator — so the CLI
// reports what it would infer and refuses until the operator opts in.
func TestEvidenceAddEvidence_InferenceRequiresTheFlag(t *testing.T) {
	pkg := writeTestEvidence(t)
	sbom := writeEvidenceArtifact(t, `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)

	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", sbom)
	require.Error(t, err, "a missing --format must not be filled in silently")
	assert.Contains(t, err.Error(), "cyclonedx", "the message must name what it would have inferred")
	assert.Contains(t, err.Error(), "--infer", "and how to accept it")
	assert.Empty(t, readEvidenceExternal(t, pkg), "nothing may be written while the format is unsettled")
}

// Inference reads the artifact's own discriminator, never its filename. A file
// named *.cdx.json holding SPDX is SPDX.
func TestEvidenceAddEvidence_InfersFromContentNotFilename(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := t.TempDir()
	misnamed := filepath.Join(dir, "webtier.cdx.json")
	require.NoError(t, os.WriteFile(misnamed,
		[]byte(`{"spdxVersion":"SPDX-2.3","name":"webtier","SPDXID":"SPDXRef-DOCUMENT"}`), 0o600))

	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--uri", misnamed, "--infer")
	require.NoError(t, err)

	ext := readEvidenceExternal(t, pkg)
	require.Len(t, ext, 1)
	assert.Equal(t, "spdx", ext[0].(map[string]interface{})["format"],
		"the content discriminator wins over a misleading .cdx.json name")
	// Assert the RECEIPT specifically, not merely that "spdx" appears anywhere on
	// stderr: the uri -> format echo also contains it, so a loose assertion passes
	// even when the inference is never reported. It did — deleting the receipt left
	// the whole suite green until this was tightened.
	assert.Contains(t, stderr, `Inferred format "spdx"`,
		"an inferred format must be reported, not applied quietly")
}

// The same URI twice is refused rather than ignored. Silently skipping would hide
// the dangerous case: the artifact at that URI has CHANGED, which a differing
// checksum proves and an evidence package must never absorb unremarked.
func TestEvidenceAddEvidence_RefusesDuplicateURI(t *testing.T) {
	pkg := writeTestEvidence(t)
	artifact := writeEvidenceArtifact(t, `{"@timestamp":"2026-01-01T00:00:00Z"}`+"\n")

	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", artifact, "--format", "ecs")
	require.NoError(t, err)

	_, _, dupErr := executeCommand("evidence", "add-evidence", pkg, "--uri", artifact, "--format", "ecs")
	require.Error(t, dupErr, "the same URI must not be listed twice")
	assert.Contains(t, dupErr.Error(), "already")
	assert.Len(t, readEvidenceExternal(t, pkg), 1, "the package must be unchanged")
}

// --checksum names ONE artifact's digest, so it cannot be shared across several.
func TestEvidenceAddEvidence_RefusesChecksumWithMultipleURIs(t *testing.T) {
	pkg := writeTestEvidence(t)

	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "https://a.example/x.ndjson", "--uri", "https://b.example/y.ndjson",
		"--format", "ecs",
		"--checksum", "0000000000000000000000000000000000000000000000000000000000000000")
	require.Error(t, err, "one checksum cannot describe two artifacts")
	assert.Contains(t, err.Error(), "--checksum")
}

// A rejected format must say what a valid one looks like. "use an x-<custom>
// value" does not tell someone who typed x-Foo or X-Splunk why it was refused —
// the case where the answer actually matters is the one it left unexplained.
func TestEvidenceAddEvidence_InvalidFormatNamesThePattern(t *testing.T) {
	pkg := writeTestEvidence(t)

	for _, bad := range []string{"stix", "x-Foo", "X-Splunk", "x-"} {
		_, _, err := executeCommand("evidence", "add-evidence", pkg,
			"--uri", "https://x.example/y.json", "--format", bad)
		require.Error(t, err, "format %q must be refused", bad)
		assert.Contains(t, err.Error(), "^x-", "the error must show the actual pattern, not a gloss")
		assert.Contains(t, err.Error(), "ecs", "and still list the reserved values")
	}
}

// The success output pairs each artifact with the format it was given. A user who
// supplies the right COUNT of --format values in the wrong ORDER gets confidently
// mislabelled artifacts; echoing the pairing is the only signal that catches it.
func TestEvidenceAddEvidence_EchoesTheURIToFormatPairing(t *testing.T) {
	pkg := writeTestEvidence(t)
	logs := writeEvidenceArtifact(t, `{"@timestamp":"2026-01-01T00:00:00Z"}`+"\n")
	sbom := writeEvidenceArtifact(t, `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)

	_, stderr, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", logs, "--uri", sbom, "--format", "ecs", "--format", "cyclonedx")
	require.NoError(t, err)

	assert.Contains(t, stderr, filepath.Base(logs)+" -> ecs")
	assert.Contains(t, stderr, filepath.Base(sbom)+" -> cyclonedx")
}

// A run that aborts must leave no receipt behind. The first artifact's inference
// succeeds and the second has no discriminator, so the whole invocation fails —
// reporting the first would claim something that never happened.
func TestEvidenceAddEvidence_AbortedRunLeavesNoInferenceReceipt(t *testing.T) {
	pkg := writeTestEvidence(t)
	sbom := writeEvidenceArtifact(t, `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)
	plain := writeEvidenceArtifact(t, `{"not":"a recognizable artifact"}`)

	_, stderr, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", sbom, "--uri", plain, "--infer")
	require.Error(t, err)
	assert.NotContains(t, stderr, "Inferred format",
		"no receipt may be printed for a run that wrote nothing")
	assert.Empty(t, readEvidenceExternal(t, pkg), "and nothing may be written")
}

// "I read it and found no discriminator" and "there was nothing to read" call for
// different fixes, so they must not share a message.
func TestEvidenceAddEvidence_DistinguishesMissingFileFromMissingDiscriminator(t *testing.T) {
	pkg := writeTestEvidence(t)

	_, _, missingErr := executeCommand("evidence", "add-evidence", pkg, "--uri", "no-such-file.json")
	require.Error(t, missingErr)
	assert.Contains(t, missingErr.Error(), "not a local file")

	plain := writeEvidenceArtifact(t, `{"not":"a recognizable artifact"}`)
	_, _, noDiscErr := executeCommand("evidence", "add-evidence", pkg, "--uri", plain)
	require.Error(t, noDiscErr)
	assert.Contains(t, noDiscErr.Error(), "no format discriminator")
	assert.NotContains(t, noDiscErr.Error(), "not a local file")
}
