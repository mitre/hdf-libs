package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Names whose bytes are Latin-1, not UTF-8.
const (
	nonUTF8Name = "caf\xe9.json"
	nonUTF8Dir  = "caf\xe9"
)

// writeNonUTF8File creates a file under a name that is not valid UTF-8, or skips where
// the filesystem refuses one (macOS APFS does); detected by trying, not by GOOS.
func writeNonUTF8File(t *testing.T, dir string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, nonUTF8Name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Skipf("this filesystem refuses a name that is not valid UTF-8: %v", err)
	}
	return path
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(evidenceFixtureDir, name))
	require.NoError(t, err)
	return data
}

// The scan skips the file, says why, and the package it writes verifies: recording
// "caf%E9.json" wrote a reference this CLI's own info --verify then called malformed.
func TestEvidenceBuild_FromDirSkipsANameThatIsNotUTF8(t *testing.T) {
	dir := scanTree(t)
	writeNonUTF8File(t, dir, fixtureBytes(t, "postgres-results.json"))
	outputPath := filepath.Join(dir, "pkg.json")

	_, stderr, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath)
	require.NoError(t, err, stderr)
	assert.Contains(t, stderr, "Skipped "+nonUTF8Name+": its name is not valid UTF-8")

	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.NotContains(t, string(data), "caf", "the unrecordable file is not listed")

	stdout, verifyStderr, _ := executeCommand("evidence", "info", outputPath, "--verify")
	assert.NotContains(t, stdout+verifyStderr, "not a valid uri-reference")
}

// Named explicitly, the same file is refused: the operator asked for it, so dropping it
// would be silent, and the error says which file and why.
func TestEvidenceBuild_RefusesANamedInputThatIsNotUTF8(t *testing.T) {
	dir := t.TempDir()
	path := writeNonUTF8File(t, dir, fixtureBytes(t, "postgres-results.json"))
	outputPath := filepath.Join(dir, "pkg.json")

	_, _, err := executeCommand("evidence", "build", "--results", path, "-o", outputPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `caf\xe9.json`, "the file is named, its bytes escaped")
	assert.Contains(t, err.Error(), "not valid UTF-8")
	assert.NoFileExists(t, outputPath)
}

// update records results through the same reference function as build.
func TestEvidenceUpdate_RefusesANamedResultsFileThatIsNotUTF8(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"system.json", "rhel9-results.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), fixtureBytes(t, name), 0o600))
	}
	pkg := filepath.Join(dir, "pkg.json")
	_, stderr, err := executeCommand("evidence", "build", "--system", filepath.Join(dir, "system.json"),
		"--results", filepath.Join(dir, "rhel9-results.json"), "-o", pkg)
	require.NoError(t, err, stderr)
	path := writeNonUTF8File(t, dir, fixtureBytes(t, "postgres-results.json"))

	_, _, err = executeCommand("evidence", "update", pkg, "--results", path, "--overwrite")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid UTF-8")
}

// Discovery skips it with the notice it gives a symlink; a literal --file is refused.
func TestEvidenceAddEvidence_DiscoverySkipsANameThatIsNotUTF8(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	writeNonUTF8File(t, dir, []byte("log bytes"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.log"), []byte("real"), 0o600))

	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", dir, "--format", "raw-log")
	require.NoError(t, err, stderr)
	assert.Contains(t, stderr, "Skipped "+nonUTF8Name+": its name is not valid UTF-8")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "real.log", refs[0].(map[string]interface{})["uri"])
}

func TestEvidenceAddEvidence_RefusesANamedFileThatIsNotUTF8(t *testing.T) {
	pkg := writeTestEvidence(t)
	path := writeNonUTF8File(t, filepath.Dir(pkg), []byte("log bytes"))
	before, err := os.ReadFile(pkg)
	require.NoError(t, err)

	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--file", path, "--format", "raw-log")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid UTF-8")
	after, _ := os.ReadFile(pkg)
	assert.Equal(t, before, after, "a refused add writes nothing")
}

// Values an operator types as a reference need no file on disk, so these run everywhere.
// JSON cannot carry the bytes either: encoding/json rewrites them to U+FFFD, which would
// record a reference to a different name.
func TestEvidenceReferenceFlags_RefuseAValueThatIsNotUTF8(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(pkg string) []string
	}{
		{"set --system-ref", func(pkg string) []string {
			return []string{"evidence", "set", pkg, "--system-ref", nonUTF8Name}
		}},
		{"set --plan-ref", func(pkg string) []string {
			return []string{"evidence", "set", pkg, "--plan-ref", nonUTF8Name}
		}},
		{"add-evidence --uri", func(pkg string) []string {
			return []string{"evidence", "add-evidence", pkg, "--uri", nonUTF8Name,
				"--format", "raw-log", "--checksum", "sha256:" + strings.Repeat("a", 64)}
		}},
		{"add-reference --href", func(pkg string) []string {
			return []string{"evidence", "add-reference", pkg, "--source-name", "ctx",
				"--href", nonUTF8Name}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := writeTestEvidence(t)
			before, err := os.ReadFile(pkg)
			require.NoError(t, err)
			_, _, err = executeCommand(tc.args(pkg)...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not valid UTF-8")
			assert.Contains(t, err.Error(), `caf\xe9.json`)
			after, _ := os.ReadFile(pkg)
			assert.Equal(t, before, after, "a refused write leaves the package as it was")
			var doc map[string]interface{}
			require.NoError(t, json.Unmarshal(after, &doc))
		})
	}
}

// A directory so named is skipped whole, as one entry, rather than reported as a
// directory the scan could not list — which --require-readable would then fail on.
func TestEvidenceBuild_FromDirSkipsADirectoryWhoseNameIsNotUTF8(t *testing.T) {
	dir := scanTree(t)
	sub := filepath.Join(dir, nonUTF8Dir)
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Skipf("this filesystem refuses a name that is not valid UTF-8: %v", err)
	}
	require.NoError(t, os.WriteFile(filepath.Join(sub, "r.json"), fixtureBytes(t, "postgres-results.json"), 0o600))
	outputPath := filepath.Join(dir, "pkg.json")

	_, stderr, err := executeCommand("evidence", "build", "--from-dir", dir, "-o", outputPath,
		"--require-readable")
	require.NoError(t, err, stderr)
	assert.Contains(t, stderr, "Skipped "+nonUTF8Dir+": its name is not valid UTF-8")
	assert.NotContains(t, stderr, "r.json")
	assert.NotContains(t, stderr, "could not be read")
}
