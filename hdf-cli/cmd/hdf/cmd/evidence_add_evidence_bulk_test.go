package cmd

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidenceAddEvidence_LocalGlobAddsEveryMatchedArtifact(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Join(filepath.Dir(pkg), "native reports")
	require.NoError(t, os.Mkdir(dir, 0o700))
	for name, fixture := range map[string]string{"a.json": "system.json", "b.json": "rhel9-results.json"} {
		data, err := os.ReadFile(filepath.Join("testdata", "evidence-verify", fixture))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o600))
	}
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--file", filepath.Join(dir, "*.json"), "--format", "x-json")
	require.NoError(t, err)
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 2)
	for i, name := range []string{"a.json", "b.json"} {
		ref := refs[i].(map[string]interface{})
		assert.Equal(t, "native%20reports/"+name, ref["uri"])
		assert.Equal(t, "x-json", ref["format"])
		data, readErr := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, readErr)
		sum := sha512.Sum512(data)
		assert.Equal(t, map[string]interface{}{"algorithm": "sha512", "value": hex.EncodeToString(sum[:])}, ref["checksum"])
	}
}

func TestEvidenceAddEvidence_Discovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		want    []string
		formats []string
	}{
		{"literal files", []string{"--file", "a.txt", "--file", "b.txt", "--format", "raw-log"}, []string{"a.txt", "b.txt"}, []string{"raw-log", "raw-log"}},
		{"overlapping globs", []string{"--file", "*.txt", "--file", "a*.txt", "--format", "raw-log"}, []string{"a.txt", "b.txt"}, []string{"raw-log", "raw-log"}},
		{"group formats", []string{"--file", "*.txt", "--file", "nested/*.json", "--format", "raw-log", "--format", "x-json"}, []string{"a.txt", "b.txt", "nested/c.json"}, []string{"raw-log", "raw-log", "x-json"}},
		{"directory", []string{"--from-dir", ".", "--format", "raw-log"}, []string{"a.txt", "b.txt"}, []string{"raw-log", "raw-log"}},
		{"recursive", []string{"--from-dir", ".", "--recursive", "--format", "raw-log"}, []string{"a.txt", "b.txt", "nested/c.json"}, []string{"raw-log", "raw-log", "raw-log"}},
		{"remote query unchanged", []string{"--uri", "https://example.test/report?x=[a]*", "--file", "a.txt", "--format", "x-remote", "--format", "raw-log"}, []string{"https://example.test/report?x=[a]*", "a.txt"}, []string{"x-remote", "raw-log"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := writeTestEvidence(t)
			dir := filepath.Dir(pkg)
			t.Chdir(dir)
			require.NoError(t, os.Mkdir("nested", 0o700))
			for _, p := range []string{"a.txt", "b.txt", "nested/c.json"} {
				require.NoError(t, os.WriteFile(p, []byte("artifact bytes"), 0o600))
			}
			_, _, err := executeCommand(append([]string{"evidence", "add-evidence", pkg}, tc.args...)...)
			require.NoError(t, err)
			refs := readEvidenceExternal(t, pkg)
			require.Len(t, refs, len(tc.want))
			for i, r := range refs {
				ref := r.(map[string]interface{})
				assert.Equal(t, tc.want[i], ref["uri"])
				assert.Equal(t, tc.formats[i], ref["format"])
			}
		})
	}
}

func TestEvidenceAddEvidence_DiscoveryFailureIsAtomic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		message string
	}{
		{"missing", []string{"--file", "absent.txt", "--format", "raw-log"}, "absent.txt"},
		{"unmatched", []string{"--file", "*.absent", "--format", "raw-log"}, "no files matched"},
		{"malformed", []string{"--file", "[", "--format", "raw-log"}, "invalid glob"},
		{"literal duplicate", []string{"--file", "a.txt", "--file", "a.txt", "--format", "raw-log"}, "already referenced"},
		{"format overlap", []string{"--file", "*.txt", "--file", "a*.txt", "--format", "raw-log", "--format", "x-other"}, "conflicting formats"},
		{"format count", []string{"--file", "*.txt", "--format", "raw-log", "--format", "x-other"}, "selector"},
		{"directory as file", []string{"--file", "nested", "--format", "raw-log"}, "regular file"},
		{"file as directory", []string{"--from-dir", "a.txt", "--format", "raw-log"}, "directory"},
		{"recursion without directory", []string{"--file", "a.txt", "--recursive", "--format", "raw-log"}, "--from-dir"},
		{"supplied checksum", []string{"--file", "a.txt", "--format", "raw-log", "--checksum", "sha256:bad"}, "--checksum"},
		{"empty directory", []string{"--from-dir", "nested", "--format", "raw-log"}, "no files"},
		{"blank selector", []string{"--file", "", "--format", "raw-log"}, "blank"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := writeTestEvidence(t)
			t.Chdir(filepath.Dir(pkg))
			require.NoError(t, os.WriteFile("a.txt", []byte("bytes"), 0o600))
			require.NoError(t, os.Mkdir("nested", 0o700))
			before, err := os.ReadFile(pkg)
			require.NoError(t, err)
			_, _, err = executeCommand(append([]string{"evidence", "add-evidence", pkg}, tc.args...)...)
			require.ErrorContains(t, err, tc.message)
			after, err := os.ReadFile(pkg)
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
}

func TestEvidenceAddEvidence_DiscoveryRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges")
	}
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	require.NoError(t, os.Symlink(dir, filepath.Join(dir, "cycle")))
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", dir, "--recursive", "--format", "raw-log")
	require.ErrorContains(t, err, "symlink")
}

func TestEvidenceAddEvidence_DiscoveryExcludesOutput(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	t.Chdir(dir)
	before, err := os.ReadFile(pkg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile("out.json", before, 0o600))
	require.NoError(t, os.WriteFile("report.json", []byte("report"), 0o600))
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--from-dir", ".", "--format", "x-json", "-o", "out.json", "--collector", "test-pipeline")
	require.NoError(t, err)
	refs := readEvidenceExternal(t, "out.json")
	require.Len(t, refs, 1)
	ref := refs[0].(map[string]interface{})
	assert.Equal(t, "report.json", ref["uri"])
	assert.Equal(t, "test-pipeline", ref["metadata"].(map[string]interface{})["collector"])
	after, err := os.ReadFile(pkg)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestEvidenceAddEvidence_DiscoveryInference(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bom.json"), []byte(`{"bomFormat":"CycloneDX"}`), 0o600))
	args := []string{"evidence", "add-evidence", pkg, "--file", filepath.Join(dir, "bom*.json")}
	_, _, err := executeCommand(args...)
	require.ErrorContains(t, err, "--infer")
	_, stderr, err := executeCommand(append(args, "--infer")...)
	require.NoError(t, err)
	assert.Contains(t, stderr, "Inferred format")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "cyclonedx", refs[0].(map[string]interface{})["format"])
	_, _, err = executeCommand(append(args, "--infer")...)
	require.ErrorContains(t, err, "already referenced")
}

func TestEvidenceAddEvidence_DiscoveryExcludesPackageAlias(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	require.NoError(t, os.Link(pkg, filepath.Join(dir, "alias.json")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "report.txt"), []byte("report"), 0o600))
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", dir, "--format", "raw-log")
	require.NoError(t, err)
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "report.txt", refs[0].(map[string]interface{})["uri"])
}

func TestEvidenceAddEvidence_DiscoveryUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not enforce Windows ACLs")
	}
	pkg := writeTestEvidence(t)
	path := filepath.Join(filepath.Dir(pkg), "locked.txt")
	require.NoError(t, os.WriteFile(path, []byte("bytes"), 0o000))
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if f, err := os.Open(path); err == nil {
		_ = f.Close()
		t.Skip("process can bypass filesystem permissions")
	}
	before, err := os.ReadFile(pkg)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--file", path, "--format", "raw-log")
	require.ErrorContains(t, err, "read selected evidence")
	after, err := os.ReadFile(pkg)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}
