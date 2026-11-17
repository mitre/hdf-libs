package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stdinPackageBytes is a package recording one results document at uri, with checksum.
func stdinPackageBytes(t *testing.T, uri, checksum string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"name": "from stdin",
		"contents": []map[string]any{{
			"type": "hdf-results", "uri": uri,
			"checksum": map[string]string{"algorithm": "sha256", "value": checksum},
		}},
	})
	require.NoError(t, err)
	return raw
}

func sha256Hex(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

// A stdin package has no directory, so a package-relative reference names nothing. info
// --verify and bundle have no output directory to stand in for one, so they refuse it
// rather than resolving it against the working directory.
func TestEvidenceReaders_RefuseAStdinPackageWithAPackageRelativeReference(t *testing.T) {
	results := fixtureBytes(t, "rhel9-results.json")
	for _, tc := range []struct {
		name string
		args func(dir string) []string
	}{
		{"info --verify", func(string) []string { return []string{"evidence", "info", "-", "--verify"} }},
		{"bundle", func(dir string) []string {
			return []string{"evidence", "bundle", "-", "-o", filepath.Join(dir, "out.zip")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			t.Chdir(cwd)
			// Present in the working directory, so resolving there would "succeed".
			require.NoError(t, os.WriteFile("r.json", results, 0o600))
			pkg := stdinPackageBytes(t, "r.json", sha256Hex(results))

			_, _, err := executeCommandWithStdin(t, pkg, tc.args(cwd)...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `"r.json"`, "the reference is named")
			assert.Contains(t, err.Error(), "read from stdin")
			assert.NoFileExists(t, filepath.Join(cwd, "out.zip"))
		})
	}
}

// An absolute reference names a file without the package's help, but nothing is INSIDE a
// stdin package's directory, so it is reported as unreachable and never read: here its
// checksum is wrong, so reading it from the working directory would report a mismatch.
func TestEvidenceInfoVerify_StdinPackageReadsNoAbsoluteReferenceAsInPackage(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	// Recorded forward-slashed: the field is a uri-reference, and a Windows separator
	// would fail schema validation before the stdin rule is reached.
	abs := filepath.Join(cwd, "r.json")
	require.NoError(t, os.WriteFile(abs, []byte("not the recorded bytes"), 0o600))
	pkg := stdinPackageBytes(t, filepath.ToSlash(abs), sha256Hex([]byte("the recorded bytes")))

	stdout, stderr, err := executeCommandWithStdin(t, pkg, "evidence", "info", "-", "--verify")
	require.NoError(t, err, "a stdin package with only absolute references proceeds; %s%s", stdout, stderr)
	assert.NotContains(t, stdout+stderr, "MISMATCH")
	assert.Contains(t, stdout+stderr, stdinNoDirectory, "the reference is reported, not dropped")
}

func TestEvidenceInfoVerify_StdinPackageWithOnlyRemoteReferencesProceeds(t *testing.T) {
	t.Chdir(t.TempDir())
	pkg := stdinPackageBytes(t, "https://evidence.example/r.json", sha256Hex([]byte("x")))
	stdout, stderr, err := executeCommandWithStdin(t, pkg, "evidence", "info", "-", "--verify")
	require.NoError(t, err, "%s%s", stdout, stderr)
}

// bundle carries nothing for a stdin package (nothing is inside its directory), and the
// package's own entry is not named "-", which no extractor can make sense of.
func TestEvidenceBundle_StdinPackageCarriesNoAbsoluteReferenceAndIsNotNamedDash(t *testing.T) {
	results := fixtureBytes(t, "rhel9-results.json")
	cwd := t.TempDir()
	t.Chdir(cwd)
	abs := filepath.Join(cwd, "r.json")
	require.NoError(t, os.WriteFile(abs, results, 0o600))
	pkg := stdinPackageBytes(t, filepath.ToSlash(abs), sha256Hex(results))
	out := filepath.Join(cwd, "out.zip")

	_, stderr, err := executeCommandWithStdin(t, pkg, "evidence", "bundle", "-", "-o", out)
	require.NoError(t, err, stderr)
	entries := zipEntries(t, out)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	assert.Equal(t, []string{stdinBundlePackageEntry}, names,
		"only the package travels, under a real name")
	assert.Equal(t, pkg, entries[stdinBundlePackageEntry])
}

// export has an output directory, so a stdin package resolves its references there, as
// the writers resolve one beside -o, rather than in the working directory.
func TestEvidenceExport_ResolvesAStdinPackageAgainstItsOutputDirectory(t *testing.T) {
	results := fixtureBytes(t, "rhel9-results.json")
	t.Chdir(t.TempDir())
	outDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "r.json"), results, 0o600))
	pkg := stdinPackageBytes(t, "r.json", sha256Hex(results))

	_, stderr, err := executeCommandWithStdin(t, pkg, "evidence", "export", "-", "--format", "oscal", "-o", outDir)
	require.NoError(t, err, stderr)
	assert.Contains(t, stderr, "1 documents exported to "+outDir)
}

// The default "-o ." would make the working directory the stdin package's base by
// accident, so export requires -o to be stated for one.
func TestEvidenceExport_RequiresAnExplicitOutputForAStdinPackage(t *testing.T) {
	results := fixtureBytes(t, "rhel9-results.json")
	cwd := t.TempDir()
	t.Chdir(cwd)
	require.NoError(t, os.WriteFile("r.json", results, 0o600))
	pkg := stdinPackageBytes(t, "r.json", sha256Hex(results))

	_, _, err := executeCommandWithStdin(t, pkg, "evidence", "export", "-", "--format", "oscal")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading the package from stdin requires -o <dir>")
	assert.NoFileExists(t, filepath.Join(cwd, "r.oscal-sar.json"), "nothing is exported")
}
