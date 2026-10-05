package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// externalEvidence is carried into the archive when it lives inside the package, so an
// absolute in-package URI has the same defect planRef had: the artifact travels under a
// relative entry name while the package names the producing machine's path. Recorded
// relatively here, for the same reason `build` and `evidence set` do it.
func TestEvidenceAddEvidence_NormalizesAnInPackageAbsoluteURI(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "logs"), 0o750))
	artifact := filepath.Join(dir, "logs", "audit.ndjson")
	require.NoError(t, os.WriteFile(artifact, []byte("{\"message\":\"x\"}\n"), 0o600))

	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", artifact, "--format", "ecs")
	require.NoError(t, err)

	ext := readEvidenceExternal(t, pkg)
	require.Len(t, ext, 1)
	entry, _ := ext[0].(map[string]interface{})
	assert.Equal(t, "logs/audit.ndjson", entry["uri"],
		"an in-package artifact is recorded relative to the package, subdirectory preserved")
	// The checksum is over the real file, so normalizing the recorded uri must not disturb it.
	cs, _ := entry["checksum"].(map[string]interface{})
	assert.NotEmpty(t, cs["value"], "the artifact's checksum is still computed and recorded")
}

// An artifact OUTSIDE the package is external by design: it is not carried, and rewriting
// its URI would claim it is somewhere it is not.
func TestEvidenceAddEvidence_LeavesAnOutOfPackageURIExactlyAsGiven(t *testing.T) {
	pkg := writeTestEvidence(t)
	outside := writeEvidenceArtifact(t, "{\"message\":\"elsewhere\"}\n") // its own TempDir
	require.False(t, strings.HasPrefix(outside, filepath.Dir(pkg)), "precondition: outside the package")

	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", outside, "--format", "ecs")
	require.NoError(t, err)

	ext := readEvidenceExternal(t, pkg)
	require.Len(t, ext, 1)
	entry, _ := ext[0].(map[string]interface{})
	assert.Equal(t, filepath.ToSlash(outside), entry["uri"], "recorded exactly as given")
}

// Normalization collapses two spellings of one artifact, which makes the duplicate visible
// to the existing same-URI guard instead of letting a second entry land for one file.
func TestEvidenceAddEvidence_NormalizationExposesADuplicateSpelling(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "logs"), 0o750))
	artifact := filepath.Join(dir, "logs", "audit.ndjson")
	require.NoError(t, os.WriteFile(artifact, []byte("{\"message\":\"x\"}\n"), 0o600))

	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", artifact, "--format", "ecs")
	require.NoError(t, err)

	// Built by concatenation, NOT filepath.Join: Join cleans its result, which would make
	// this string identical to the first and the test would pass without the code doing
	// anything. The point is an UNCLEANED spelling of the same artifact.
	dotted := dir + "/logs/../logs/audit.ndjson"
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--uri", dotted, "--format", "ecs")
	require.Error(t, err, "the same artifact spelled differently is still the same artifact")
	assert.Contains(t, err.Error(), "already referenced")
	assert.Len(t, readEvidenceExternal(t, pkg), 1, "and no second entry lands for one file")
}

// This file passed -o nowhere, so the branch was wholly untested here. See the sibling
// tests in evidence_set_test.go.
func TestEvidenceAddEvidence_OutputPathLeavesTheInputUntouched(t *testing.T) {
	t.Run("-o writes elsewhere and the input is byte-identical", func(t *testing.T) {
		pkg := writeTestEvidence(t)
		before, err := os.ReadFile(pkg)
		require.NoError(t, err)
		artifact := writeEvidenceArtifact(t, "{\"message\":\"x\"}\n")
		out := filepath.Join(filepath.Dir(pkg), "elsewhere.json")

		_, _, err = executeCommand("evidence", "add-evidence", pkg,
			"--uri", artifact, "--format", "ecs", "-o", out)
		require.NoError(t, err)

		assert.Len(t, readEvidenceExternal(t, out), 1, "the named output carries the entry")
		after, err := os.ReadFile(pkg)
		require.NoError(t, err)
		assert.Equal(t, before, after, "and the input is untouched")
	})

	t.Run("without -o the input is replaced in place", func(t *testing.T) {
		pkg := writeTestEvidence(t)
		artifact := writeEvidenceArtifact(t, "{\"message\":\"x\"}\n")
		_, _, err := executeCommand("evidence", "add-evidence", pkg,
			"--uri", artifact, "--format", "ecs")
		require.NoError(t, err)
		assert.Len(t, readEvidenceExternal(t, pkg), 1, "the default is to amend in place")
	})
}

// A reference is relative to the PACKAGE's directory — the contract bundle and verify both
// obey — but the checksum was computed by reading --uri against the process CWD. The test
// process's CWD is this Go package, never the temp directory holding the package under
// test, so these cases are the real pipeline shape: the package and its artifacts sit in an
// artifacts directory while the job's CWD is the repo root.
func TestEvidenceAddEvidence_ChecksumsAPackageRelativeURIFromAnotherDirectory(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scans"), 0o750))
	artifact := filepath.Join(dir, "scans", "audit.ndjson")
	body := []byte("{\"message\":\"beside the package\"}\n")
	require.NoError(t, os.WriteFile(artifact, body, 0o600))
	sum := sha256.Sum256(body)

	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "scans/audit.ndjson", "--format", "ecs")
	require.NoError(t, err)

	ext := readEvidenceExternal(t, pkg)
	require.Len(t, ext, 1)
	entry, _ := ext[0].(map[string]interface{})
	assert.Equal(t, "scans/audit.ndjson", entry["uri"],
		"the uri is recorded exactly as typed; only resolution for hashing changes")
	cs, _ := entry["checksum"].(map[string]interface{})
	require.NotNil(t, cs, "a package-relative artifact beside the package must be hashed")
	assert.Equal(t, hex.EncodeToString(sum[:]), cs["value"],
		"and the recorded digest must be of THAT file, not one found via the CWD")
}

// The half that makes the bug dangerous rather than merely unhelpful: when a file exists
// at the same relative spelling under the CWD, the package recorded a checksum for a file
// the reference does not name, and `bundle` then refused it as a mismatch — accusing the
// operator's evidence of tampering.
//
// A DECOY is what makes this test able to fail. Without one the assertion cannot
// distinguish "hashed the file the reference names" from "hashed the only file there was",
// and the test is a duplicate of its sibling under a different name. t.Chdir puts the
// process in the decoy's directory, which is the pipeline shape: CWD is the repo root,
// the package lives in an artifacts directory.
func TestEvidenceAddEvidence_NeverHashesAFileTheReferenceDoesNotName(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "artifacts")
	require.NoError(t, os.MkdirAll(filepath.Join(pkgDir, "scans"), 0o750))
	pkg := filepath.Join(pkgDir, "evidence.json")
	require.NoError(t, os.WriteFile(pkg, []byte(testEvidencePackage), 0o600))

	beside := []byte("{\"message\":\"beside the package\"}\n")
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "scans", "audit.ndjson"), beside, 0o600))
	besideSum := sha256.Sum256(beside)

	// The decoy: same relative spelling, different bytes, reachable from the CWD.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "scans"), 0o750))
	decoy := []byte("{\"message\":\"DECOY under the CWD\"}\n")
	require.NoError(t, os.WriteFile(filepath.Join(root, "scans", "audit.ndjson"), decoy, 0o600))
	require.NotEqual(t, beside, decoy, "precondition: the two files must differ")
	t.Chdir(root)

	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "scans/audit.ndjson", "--format", "ecs")
	require.NoError(t, err)

	entry, _ := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
	cs, _ := entry["checksum"].(map[string]interface{})
	require.NotNil(t, cs)
	assert.Equal(t, hex.EncodeToString(besideSum[:]), cs["value"],
		"the digest must be of the file the reference names, not the decoy under the CWD")
	decoySum := sha256.Sum256(decoy)
	assert.NotEqual(t, hex.EncodeToString(decoySum[:]), cs["value"],
		"and emphatically not the decoy's")
}

// A genuinely absent artifact stays a notice, not a failure — and the notice names the path
// actually tried, so an operator can see where it looked.
func TestEvidenceAddEvidence_AbsentArtifactNamesThePathItTried(t *testing.T) {
	pkg := writeTestEvidence(t)

	_, stderr, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "scans/missing.ndjson", "--format", "ecs")
	require.NoError(t, err, "an absent artifact is a notice, not a hard failure")

	entry, _ := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
	assert.Nil(t, entry["checksum"], "no checksum is recorded for an artifact that is not there")
	assert.Contains(t, stderr, "no local file to hash", "the existing notice still prints")
	assert.Contains(t, stderr, filepath.Join(filepath.Dir(pkg), "scans", "missing.ndjson"),
		"and it names the path actually tried, not just the uri as typed")
}

// An absolute --uri is taken as given, exactly as before: the package may legitimately
// reference an artifact it does not contain, and resolving one against the package would
// claim it is somewhere it is not.
func TestEvidenceAddEvidence_AbsoluteURIIsHashedAsGiven(t *testing.T) {
	pkg := writeTestEvidence(t)
	body := "{\"message\":\"elsewhere\"}\n"
	outside := writeEvidenceArtifact(t, body) // its own TempDir, outside the package
	sum := sha256.Sum256([]byte(body))

	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", outside, "--format", "ecs")
	require.NoError(t, err)

	entry, _ := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
	cs, _ := entry["checksum"].(map[string]interface{})
	require.NotNil(t, cs, "an absolute path is still hashed")
	assert.Equal(t, hex.EncodeToString(sum[:]), cs["value"])
}

// Resolution is confined to the package: a traversal and a symlink leading out are both
// refused rather than followed, so no digest is ever recorded for bytes outside it.
func TestEvidenceAddEvidence_ResolutionDoesNotLeaveThePackage(t *testing.T) {
	t.Run("parent traversal is not followed", func(t *testing.T) {
		pkg := writeTestEvidence(t)
		dir := filepath.Dir(pkg)
		// A real file one level up, which a naive join would reach and hash.
		up := filepath.Join(filepath.Dir(dir), "outside.ndjson")
		require.NoError(t, os.WriteFile(up, []byte("{\"message\":\"outside\"}\n"), 0o600))
		// WITHOUT this the subtest passes for the wrong reason: the test process's CWD is
		// the Go source directory, where ../outside.ndjson does not exist, so nothing is
		// hashed whether or not resolution is confined. Standing in the package directory
		// makes the file reachable BOTH ways, so only real confinement keeps it unhashed.
		t.Chdir(dir)

		_, _, err := executeCommand("evidence", "add-evidence", pkg,
			"--uri", "../outside.ndjson", "--format", "ecs")
		require.NoError(t, err, "a reference the package does not contain is recorded, not refused")

		entry, _ := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
		assert.Equal(t, "../outside.ndjson", entry["uri"], "recorded exactly as typed")
		assert.Nil(t, entry["checksum"],
			"and NOT hashed: resolution may not leave the package to find it")
	})

	t.Run("a symlink out of the package is not followed", func(t *testing.T) {
		pkg := writeTestEvidence(t)
		dir := filepath.Dir(pkg)
		outsideDir := t.TempDir()
		target := filepath.Join(outsideDir, "secret.ndjson")
		require.NoError(t, os.WriteFile(target, []byte("{\"message\":\"outside\"}\n"), 0o600))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "scans"), 0o750))
		require.NoError(t, os.Symlink(target, filepath.Join(dir, "scans", "link.ndjson")))

		t.Chdir(dir) // as above: make the target reachable from the CWD too

		_, _, err := executeCommand("evidence", "add-evidence", pkg,
			"--uri", "scans/link.ndjson", "--format", "ecs")
		require.NoError(t, err)

		entry, _ := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
		assert.Nil(t, entry["checksum"],
			"a symlink leaving the package is not followed, so nothing outside is hashed")
	})
}

// The severe mode again, through the route that survived the first attempt at this card:
// with the PACKAGE PATH typed relatively, the resolution base was relative too, so
// SafePath related a relative base to an absolute symlink target, filepath.Rel errored,
// the boundary failed closed, and the old raw-uri fallback then hashed whatever the CWD
// offered. Correctness must not depend on how the operator spelled the package path.
func TestEvidenceAddEvidence_ARelativePackagePathResolvesTheSameWay(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "artifacts")
	require.NoError(t, os.MkdirAll(filepath.Join(pkgDir, "scans"), 0o750))
	pkg := filepath.Join(pkgDir, "evidence.json")
	require.NoError(t, os.WriteFile(pkg, []byte(testEvidencePackage), 0o600))

	// The real artifact, reached through an in-package symlink with an ABSOLUTE target.
	target := filepath.Join(pkgDir, "scans", "real.ndjson")
	body := []byte("{\"message\":\"the real in-package artifact\"}\n")
	require.NoError(t, os.WriteFile(target, body, 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(pkgDir, "scans", "audit.ndjson")))
	wantSum := sha256.Sum256(body)

	// A decoy at the same relative spelling, reachable from the CWD.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "scans"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "scans", "audit.ndjson"),
		[]byte("{\"message\":\"DECOY\"}\n"), 0o600))
	t.Chdir(root)

	// The package path is RELATIVE here — that is the point of the test.
	_, _, err := executeCommand("evidence", "add-evidence", filepath.Join("artifacts", "evidence.json"),
		"--uri", "scans/audit.ndjson", "--format", "ecs")
	require.NoError(t, err)

	entry, _ := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
	cs, _ := entry["checksum"].(map[string]interface{})
	require.NotNil(t, cs, "an in-package symlink is a legitimate artifact and must be hashed")
	assert.Equal(t, hex.EncodeToString(wantSum[:]), cs["value"],
		"and hashed through the symlink to the in-package file, not the CWD decoy")
}

// --infer reads the artifact's own content to name its format, so it must resolve exactly
// as hashing does. Reading from the CWD reported a package-relative artifact sitting
// beside the package as "not a local file" and refused the command outright.
func TestEvidenceAddEvidence_InferResolvesAgainstThePackageDirectory(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "artifacts")
	require.NoError(t, os.MkdirAll(pkgDir, 0o750))
	pkg := filepath.Join(pkgDir, "evidence.json")
	require.NoError(t, os.WriteFile(pkg, []byte(testEvidencePackage), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "sbom.cdx.json"),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`), 0o600))
	t.Chdir(root) // CWD is not the package directory

	_, _, err := executeCommand("evidence", "add-evidence", pkg,
		"--uri", "sbom.cdx.json", "--infer")
	require.NoError(t, err, "--infer must find an artifact beside the package")

	entry, _ := readEvidenceExternal(t, pkg)[0].(map[string]interface{})
	assert.Equal(t, "cyclonedx", entry["format"],
		"and read the format from that artifact's own content discriminator")
}

// --infer's failure messages must be true about the operator's filesystem. The stat that
// chooses between them has to use the same resolution the content read uses: statting the
// raw uri against the CWD called an artifact sitting beside the package "not a local
// file", and the accurate message was reachable only when the operator happened to be
// standing in the package directory.
func TestEvidenceAddEvidence_InferFailureMessagesAreTrueFromAnyDirectory(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "artifacts")
	require.NoError(t, os.MkdirAll(pkgDir, 0o750))
	pkg := filepath.Join(pkgDir, "evidence.json")
	require.NoError(t, os.WriteFile(pkg, []byte(testEvidencePackage), 0o600))
	// Beside the package, readable, but carrying no format discriminator.
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "plain.json"),
		[]byte(`{"hello":"no discriminator"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "up.json"),
		[]byte(`{"hello":"outside"}`), 0o600))
	t.Chdir(root) // deliberately NOT the package directory

	t.Run("a readable artifact beside the package is not called non-local", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", "plain.json", "--infer")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "carries no format discriminator",
			"it was read and had nothing to find")
		assert.NotContains(t, err.Error(), "not a local file",
			"it IS a local file — it sits beside the package")
	})

	t.Run("a reference outside the package says so", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", "../up.json", "--infer")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not resolve inside the package's directory",
			"the boundary refused it; that is a different fix from a missing discriminator")
		assert.NotContains(t, err.Error(), "not a local file")
	})

	t.Run("a genuinely absent artifact is still called non-local", func(t *testing.T) {
		_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", "nope.json", "--infer")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a local file", "nothing was there to read")
	})
}
