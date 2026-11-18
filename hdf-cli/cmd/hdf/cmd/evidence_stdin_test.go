package cmd

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A package read from stdin has no file to write back to, so a writing command refuses
// rather than creating a regular file literally named "-" in the working directory.
func TestEvidenceWriters_RefuseAStdinPackageWithoutAnOutput(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"add-evidence", []string{"evidence", "add-evidence", "-", "--uri", "https://lake.example/q1/",
			"--format", "ocsf"}, "reading the package from stdin requires -o <file>"},
		{"add-reference", []string{"evidence", "add-reference", "-", "--source-name", "cve",
			"--external-id", "CVE-2021-44228"}, "reading the package from stdin requires -o <file>"},
		{"set", []string{"evidence", "set", "-", "--name", "renamed"},
			"reading the package from stdin requires -o <file>"},
		{"update", []string{"evidence", "update", "-", "--results", "r.json"},
			"reading the package from stdin requires -o <file>"},
		{"update --overwrite", []string{"evidence", "update", "-", "--results", "r.json", "--overwrite"},
			"--overwrite replaces the input package"},
		{"update --dry-run", []string{"evidence", "update", "-", "--results", "r.json", "--dry-run"},
			"reading the package from stdin requires -o <file>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pkgPath := referencePackage(t)
			pkg, err := os.ReadFile(pkgPath)
			require.NoError(t, err)
			results := fixtureBytes(t, "postgres-results.json")
			cwd := t.TempDir()
			t.Chdir(cwd)
			require.NoError(t, os.WriteFile("r.json", results, 0o600))

			_, _, err = executeCommandWithStdin(t, pkg, tc.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NoFileExists(t, filepath.Join(cwd, "-"), "no stray file named - is written")
		})
	}
}

// With -o the stdin package is written there, and that file is the package's only home,
// so package-relative references resolve beside it rather than in the working directory.
func TestEvidenceWriters_ResolveAStdinPackageAgainstItsOutput(t *testing.T) {
	setup := func(t *testing.T) (pkg []byte, outDir string) {
		t.Helper()
		_, pkgPath := referencePackage(t)
		pkg, err := os.ReadFile(pkgPath)
		require.NoError(t, err)
		cwd := t.TempDir()
		t.Chdir(cwd)
		outDir = t.TempDir()
		// The same relative name in both places, with different bytes, so the digest
		// says which one was read.
		require.NoError(t, os.WriteFile(filepath.Join(cwd, "art.txt"), []byte("cwd copy"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(outDir, "art.txt"), []byte("package copy"), 0o600))
		return pkg, outDir
	}
	packageCopy := sha512.Sum512([]byte("package copy"))
	want := hex.EncodeToString(packageCopy[:])

	t.Run("add-reference", func(t *testing.T) {
		pkg, outDir := setup(t)
		out := filepath.Join(outDir, "pkg.json")
		_, stderr, err := executeCommandWithStdin(t, pkg, "evidence", "add-reference", "-",
			"--source-name", "notes", "--href", "art.txt", "-o", out)
		require.NoError(t, err, stderr)
		refs := readPackage(t, out)["externalReferences"].([]any)
		require.Len(t, refs, 1)
		cs := refs[0].(map[string]any)["checksum"].(map[string]any)
		assert.Equal(t, want, cs["value"], "hashed beside the output, not in the working directory")
		assert.NoFileExists(t, "-")
	})

	t.Run("add-evidence", func(t *testing.T) {
		pkg, outDir := setup(t)
		out := filepath.Join(outDir, "pkg.json")
		_, stderr, err := executeCommandWithStdin(t, pkg, "evidence", "add-evidence", "-",
			"--uri", "art.txt", "--format", "raw-log", "-o", out)
		require.NoError(t, err, stderr)
		refs := readPackage(t, out)["externalEvidence"].([]any)
		require.Len(t, refs, 1)
		cs := refs[0].(map[string]any)["checksum"].(map[string]any)
		assert.Equal(t, want, cs["value"], "hashed beside the output, not in the working directory")
		assert.NoFileExists(t, "-")
	})

	t.Run("update", func(t *testing.T) {
		pgResults := fixtureBytes(t, "postgres-results.json")
		system := fixtureBytes(t, "system.json")
		pkg, outDir := setup(t)
		require.NoError(t, os.WriteFile(filepath.Join(outDir, "system.json"), system, 0o600))
		require.NoError(t, os.MkdirAll(filepath.Join(outDir, "scans"), 0o750))
		results := filepath.Join(outDir, "scans", "pg.json")
		require.NoError(t, os.WriteFile(results, pgResults, 0o600))
		out := filepath.Join(outDir, "pkg.json")
		_, stderr, err := executeCommandWithStdin(t, pkg, "evidence", "update", "-",
			"--results", results, "-o", out)
		require.NoError(t, err, stderr)
		assert.Contains(t, recordedReferenceValues(t, out, "contents"), "scans/pg.json",
			"recorded relative to the package it was written as")
		assert.NoFileExists(t, "-")
	})
}
