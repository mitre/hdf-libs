package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
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
		assert.Equal(t, map[string]interface{}{"algorithm": evidenceDigestAlgo, "value": evidenceDigestHex(data)}, ref["checksum"])
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

// Every row here is refused inside expandEvidenceInputs, before the package is opened,
// so what each pins is the refusal and its exit code — not atomicity, which a package
// nothing has read cannot demonstrate. The Long text promises 4 when nothing matched
// and 1 for every other refusal. "Before the package is opened" is asserted, not
// trusted: each row runs against a package of garbage bytes, which the read refuses
// with a different message than the one expected here.
func TestEvidenceAddEvidence_ExpansionRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		message string
		code    int
	}{
		{"missing", []string{"--file", "absent.txt", "--format", "raw-log"}, "absent.txt", 1},
		{"unmatched", []string{"--file", "*.absent", "--format", "raw-log"}, "no files matched", 4},
		{"malformed", []string{"--file", "[", "--format", "raw-log"}, "invalid glob", 1},
		{"literal duplicate", []string{"--file", "a.txt", "--file", "a.txt", "--format", "raw-log"}, "selected twice", 1},
		{"format overlap", []string{"--file", "*.txt", "--file", "a*.txt", "--format", "raw-log", "--format", "x-other"}, "conflicting formats", 1},
		{"format count", []string{"--file", "*.txt", "--format", "raw-log", "--format", "x-other"}, "selector", 1},
		{"directory as file", []string{"--file", "nested", "--format", "raw-log"}, "regular file", 1},
		{"file as directory", []string{"--from-dir", "a.txt", "--format", "raw-log"}, "is not a directory", 1},
		{"recursion without directory", []string{"--file", "a.txt", "--recursive", "--format", "raw-log"}, "--from-dir", 1},
		{"supplied checksum", []string{"--file", "a.txt", "--format", "raw-log", "--checksum", "sha256:bad"}, "--checksum", 1},
		{"empty directory", []string{"--from-dir", "nested", "--format", "raw-log"}, "no files", 4},
		{"blank selector", []string{"--file", "", "--format", "raw-log"}, "blank", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := writeTestEvidence(t)
			t.Chdir(filepath.Dir(pkg))
			require.NoError(t, os.WriteFile("a.txt", []byte("bytes"), 0o600))
			require.NoError(t, os.Mkdir("nested", 0o700))
			require.NoError(t, os.WriteFile(pkg, []byte("not a package"), 0o600))
			_, _, err := executeCommand(append([]string{"evidence", "add-evidence", pkg}, tc.args...)...)
			require.ErrorContains(t, err, tc.message)
			assert.NotContains(t, err.Error(), "evidence package", "the package must not have been read")
			assert.Equal(t, tc.code, exitCodeOf(t, err))
		})
	}
}

// A failure AFTER the package is read must write nothing — the only place atomicity can
// be seen. Each row's setup leaves a batch that expansion accepts and the per-uri loop
// then refuses: a reference the package already carries, and a file the hasher cannot
// open after an earlier one in the same batch hashed fine.
func TestEvidenceAddEvidence_DiscoveryFailureIsAtomic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, pkg string)
		args    []string
		message string
	}{
		{"already referenced", func(t *testing.T, pkg string) {
			_, _, err := executeCommand("evidence", "add-evidence", pkg, "--file", "a.txt", "--format", "raw-log")
			require.NoError(t, err)
		}, []string{"--file", "a.txt", "--format", "raw-log"}, "already referenced"},
		{"unreadable after a hashed sibling", func(t *testing.T, pkg string) {
			if runtime.GOOS == "windows" {
				t.Skip("POSIX mode bits do not enforce Windows ACLs")
			}
			require.NoError(t, os.WriteFile("locked.txt", []byte("bytes"), 0o000))
			t.Cleanup(func() { _ = os.Chmod("locked.txt", 0o600) })
			if f, err := os.Open("locked.txt"); err == nil {
				_ = f.Close()
				t.Skip("process can bypass filesystem permissions")
			}
		}, []string{"--file", "*.txt", "--format", "raw-log"}, "to checksum it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := writeTestEvidence(t)
			t.Chdir(filepath.Dir(pkg))
			require.NoError(t, os.WriteFile("a.txt", []byte("bytes"), 0o600))
			tc.setup(t, pkg)
			before, err := os.ReadFile(pkg)
			require.NoError(t, err)
			_, _, err = executeCommand(append([]string{"evidence", "add-evidence", pkg}, tc.args...)...)
			require.ErrorContains(t, err, tc.message)
			after, err := os.ReadFile(pkg)
			require.NoError(t, err)
			assert.Equal(t, before, after, "a failure after the package was read must write nothing")
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
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.log"), []byte("real"), 0o600))
	// A symlink that would cycle is skipped with a notice, not followed and not fatal; the
	// walk sees one real file exactly once.
	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", dir, "--recursive", "--format", "raw-log")
	require.NoError(t, err)
	assert.Contains(t, stderr, "a symlink")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "real.log", refs[0].(map[string]interface{})["uri"])
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
	// Readability is proven by the one open the hasher performs, not by a probe
	// beforehand; the error therefore names the checksum step.
	require.ErrorContains(t, err, "to checksum it")
	after, err := os.ReadFile(pkg)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// Names from the filesystem are not references: a file called a%2Fb.json must be
// recorded as a%252Fb.json, which Decodes back to the on-disk name. Recording the raw
// name let packageRelativeIfInside Decode it into a/b.json, a file that does not
// exist, attested with the real file's digest.
func TestEvidenceAddEvidence_DiscoveryEncodesFilesystemNames(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	for _, name := range []string{"a%2Fb.log", "report x.log", "100%.log", "x#y.log"} {
		require.NoError(t, os.WriteFile(name, []byte("bytes for "+name), 0o600))
	}
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--file", "*.log", "--format", "raw-log")
	require.NoError(t, err)
	refs := readEvidenceExternal(t, pkg)
	var uris []string
	for _, r := range refs {
		uris = append(uris, r.(map[string]interface{})["uri"].(string))
	}
	assert.ElementsMatch(t, []string{"100%25.log", "a%252Fb.log", "report%20x.log", "x%23y.log"}, uris)
	for _, u := range uris {
		decoded, decErr := evidenceref.Decode(u)
		require.NoError(t, decErr)
		_, statErr := os.Stat(string(decoded))
		assert.NoError(t, statErr, "recorded uri %q must decode to a file that exists", u)
	}
	// The read side must resolve every recorded name, not merely a test's own Decode.
	// Asserted per reference: the seeded package carries a results.json that exists
	// nowhere, so the run as a whole is never clean.
	stdout, _, _ := executeCommand("evidence", "info", pkg, "--verify")
	for _, u := range uris {
		assert.Contains(t, stdout, "✓ "+u+" ("+evidenceDigestAlgo+" match)", "info --verify must reach %q", u)
	}
}

// A discovered file outside the package directory is refused, not recorded as an
// absolute host path: the normalization comment calls that a shape a package must not
// carry, and --uri is the way to name an external artifact on purpose.
func TestEvidenceAddEvidence_DiscoveryRefusesOutOfPackage(t *testing.T) {
	pkg := writeTestEvidence(t)
	outside := filepath.Join(t.TempDir(), "l.txt")
	require.NoError(t, os.WriteFile(outside, []byte("log"), 0o600))
	before, err := os.ReadFile(pkg)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--file", outside, "--format", "raw-log")
	require.Error(t, err)
	assert.ErrorContains(t, err, "outside the package")
	assert.ErrorContains(t, err, "--uri")
	assert.Equal(t, 1, exitCodeOf(t, err))
	// Both names travel through %q, which escapes a Windows separator; the expectation
	// takes the same route so the comparison is of the string the command printed.
	assert.ErrorContains(t, err, fmt.Sprintf("%q", outside), "the refused file is named")
	pkgDirAbs, absErr := filepath.Abs(filepath.Dir(pkg))
	require.NoError(t, absErr)
	assert.ErrorContains(t, err, fmt.Sprintf("%q", pkgDirAbs), "the package directory is named, absolute")
	after, err := os.ReadFile(pkg)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a refused selection must write nothing")
}

// The containment decision must hold on a package whose directory is reached through a
// symlink (on macOS every t.TempDir() is, via /var -> /private/var) in BOTH directions:
// an in-package file is accepted, an out-of-package one refused. A lexical-only
// comparison gets exactly this case wrong, which is why packageSubtreeRef resolves
// both sides.
func TestEvidenceAddEvidence_DiscoveryContainmentThroughSymlinkedBase(t *testing.T) {
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	resolved, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	if resolved == dir {
		t.Skip("package directory has no symlink component on this platform; the case is covered where it does")
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "in.log"), []byte("in"), 0o600))
	// Named by its RESOLVED spelling while the package stays under the unresolved
	// one: the two strings share no prefix, so packageSubtreeRef's lexical attempt
	// cannot accept it and acceptance can only come from the resolved comparison.
	// Spelled the same as the package, the lexical attempt wins and a lexical-only
	// containment passes this test.
	inResolved := filepath.Join(resolved, "in.log")
	require.False(t, strings.HasPrefix(inResolved, dir+string(os.PathSeparator)),
		"precondition: the resolved spelling must not share the unresolved base as a prefix")
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--file", inResolved, "--format", "raw-log")
	require.NoError(t, err, "an in-package file under a symlinked base must be accepted")
	assert.Equal(t, "in.log", readEvidenceExternal(t, pkg)[0].(map[string]interface{})["uri"])

	outside := filepath.Join(t.TempDir(), "out.log")
	require.NoError(t, os.WriteFile(outside, []byte("out"), 0o600))
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--file", outside, "--format", "raw-log")
	assert.ErrorContains(t, err, "outside the package")
}

// ---- card hdf-libs-xfhfs.3: one symlink and non-regular policy ----

// A symlinked --from-dir root is resolved and walked the way evidence build's
// --from-dir is, so both spellings record the same package-relative references,
// named by the resolved directory; no lexical check on the typed string decides it.
func TestEvidenceAddEvidence_DirectorySymlinkRootResolvedLikeBuild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges")
	}
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.Mkdir("logs", 0o700))
	require.NoError(t, os.WriteFile(filepath.Join("logs", "a.log"), []byte("a"), 0o600))
	require.NoError(t, os.Symlink("logs", "logslink"))
	before, err := os.ReadFile(pkg)
	require.NoError(t, err)
	for _, spelling := range []string{"logslink", "logslink/"} {
		require.NoError(t, os.WriteFile(pkg, before, 0o600))
		_, _, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", spelling, "--format", "raw-log")
		require.NoError(t, err, "spelling %q", spelling)
		refs := readEvidenceExternal(t, pkg)
		require.Len(t, refs, 1, "spelling %q", spelling)
		assert.Equal(t, "logs/a.log", refs[0].(map[string]interface{})["uri"], "spelling %q", spelling)
	}
}

// A subdirectory met without --recursive is reported the way a glob reports one,
// so the two selectors never disagree about a directory entry.
func TestEvidenceAddEvidence_FromDirReportsSkippedSubdirectoryLikeGlob(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.MkdirAll(filepath.Join("logs", "sub"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join("logs", "l.txt"), []byte("l"), 0o600))
	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", "logs", "--format", "raw-log")
	require.NoError(t, err)
	assert.Contains(t, stderr, "Skipped logs/sub: a directory")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "logs/l.txt", refs[0].(map[string]interface{})["uri"])
}

// A glob that matches a subdirectory skips it the way the directory walk does, instead
// of aborting the whole batch — a reports folder with one subfolder is the common case.
func TestEvidenceAddEvidence_GlobSkipsSubdirectoryLikeTheWalk(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.MkdirAll(filepath.Join("logs", "archive"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join("logs", "l.txt"), []byte("l"), 0o600))
	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--file", "logs/*", "--format", "raw-log")
	require.NoError(t, err)
	assert.Contains(t, stderr, "Skipped logs/archive: a directory.")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "logs/l.txt", refs[0].(map[string]interface{})["uri"])
}

// A discovered symlink is skipped with a notice naming its kind and the batch continues
// — the same skip-and-report `evidence build --from-dir` gives it — not aborted.
func TestEvidenceAddEvidence_DiscoveredSymlinkSkippedWithNotice(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges")
	}
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.Mkdir("evidence", 0o700))
	require.NoError(t, os.WriteFile(filepath.Join("evidence", "in.log"), []byte("in"), 0o600))
	require.NoError(t, os.Symlink("in.log", filepath.Join("evidence", "link.log")))
	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", "evidence", "--format", "raw-log")
	require.NoError(t, err, "a discovered symlink is skipped, not fatal")
	assert.Contains(t, stderr, "Skipped evidence/link.log: a symlink. Name its target explicitly if it belongs in the package.")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "evidence/in.log", refs[0].(map[string]interface{})["uri"])
}

// --no-follow-symlinks is the CLI's one symlink policy; the --uri hashing path must
// honor it rather than open the file directly past readFromFile's gate.
func TestEvidenceAddEvidence_URIHonoursNoFollowSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges")
	}
	pkg := writeTestEvidence(t)
	dir := filepath.Dir(pkg)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "in.log"), []byte("in"), 0o600))
	require.NoError(t, os.Symlink("in.log", filepath.Join(dir, "link.log")))
	_, _, err := executeCommand("--no-follow-symlinks", "evidence", "add-evidence", pkg, "--uri", "link.log", "--format", "raw-log")
	require.Error(t, err)
	assert.ErrorContains(t, err, "refusing to follow symlink")
	assert.Empty(t, readEvidenceExternal(t, pkg))
}

// One Lstat first, its FileInfo handed to both checks: a symlink that points AT the
// package is classified as a symlink — refused when named literally, skipped with the
// symlink notice when discovered — never silently absorbed as "the package itself".
func TestEvidenceAddEvidence_SymlinkToPackageIsASymlinkFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges")
	}
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.Mkdir("only", 0o700))
	require.NoError(t, os.Symlink(filepath.Join("..", filepath.Base(pkg)), filepath.Join("only", "l.json")))
	_, _, literal := executeCommand("evidence", "add-evidence", pkg, "--file", filepath.Join("only", "l.json"), "--format", "raw-log")
	require.Error(t, literal)
	assert.ErrorContains(t, literal, "symlink")
	assert.NotContains(t, literal.Error(), "package or output itself")
	_, stderr, discovered := executeCommand("evidence", "add-evidence", pkg, "--from-dir", "only", "--format", "raw-log")
	require.Error(t, discovered, "the sole entry was skipped, so nothing was selected")
	assert.ErrorContains(t, discovered, "no files selected")
	assert.Contains(t, stderr, "a symlink")
	assert.NotContains(t, stderr, "package or output itself")
}

// ---- card hdf-libs-xfhfs.5: hidden entries and one validation per format ----

// Discovery skips hidden entries and whole hidden subtrees, and says how many; the
// README's own --from-dir --recursive example must not attest .DS_Store or .git/.
func TestEvidenceAddEvidence_DiscoverySkipsDotfiles(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.MkdirAll(filepath.Join("d", ".git", "objects"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join("d", ".git", "objects", "x"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join("d", ".DS_Store"), []byte("ds"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join("d", "r.txt"), []byte("r"), 0o600))
	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", "d", "--recursive", "--format", "raw-log")
	require.NoError(t, err)
	assert.Contains(t, stderr, "Skipped 2 hidden")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "d/r.txt", refs[0].(map[string]interface{})["uri"])
}

// A glob is discovery too: it never selects a hidden entry.
func TestEvidenceAddEvidence_GlobSkipsDotfiles(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.Mkdir("d", 0o700))
	require.NoError(t, os.WriteFile(filepath.Join("d", ".hidden.log"), []byte("h"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join("d", "r.log"), []byte("r"), 0o600))
	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--file", "d/*", "--format", "raw-log")
	require.NoError(t, err)
	assert.Contains(t, stderr, "Skipped 1 hidden")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, "d/r.log", refs[0].(map[string]interface{})["uri"])
}

// Characterization: a dotfile the operator names literally is selected — the skip is
// discovery's rule, not --file's.
func TestEvidenceAddEvidence_LiteralDotfileSelected(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.WriteFile(".env.log", []byte("e"), 0o600))
	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--file", ".env.log", "--format", "raw-log")
	require.NoError(t, err)
	assert.NotContains(t, stderr, "hidden")
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	assert.Equal(t, ".env.log", refs[0].(map[string]interface{})["uri"])
}

// A batch validates each DISTINCT --format value once; the schema is not re-read
// per selected file.
func TestEvidenceAddEvidence_FormatValidatedOncePerDistinctValue(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.Mkdir("logs", 0o700))
	for i := 0; i < 50; i++ {
		require.NoError(t, os.WriteFile(filepath.Join("logs", fmt.Sprintf("%02d.log", i)), []byte("l"), 0o600))
	}
	loads := 0
	underlying := evidenceSchemaBytes
	evidenceSchemaBytes = func(kind validators.SchemaType) ([]byte, error) {
		loads++
		return underlying(kind)
	}
	t.Cleanup(func() { evidenceSchemaBytes = underlying })
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", "logs", "--format", "raw-log")
	require.NoError(t, err)
	require.Len(t, readEvidenceExternal(t, pkg), 50)
	assert.Equal(t, 1, loads, "one schema read per distinct format value")
}

// ---- card hdf-libs-xfhfs.4: order-independent dedup, one exclusion, one count rule ----

// The same two selections in either order yield the same entries and the same exit.
func TestEvidenceAddEvidence_DedupIsOrderIndependent(t *testing.T) {
	for _, order := range [][]string{
		{"--file", "a.txt", "--file", "*.txt"},
		{"--file", "*.txt", "--file", "a.txt"},
	} {
		pkg := writeTestEvidence(t)
		t.Chdir(filepath.Dir(pkg))
		require.NoError(t, os.WriteFile("a.txt", []byte("a"), 0o600))
		require.NoError(t, os.WriteFile("b.txt", []byte("b"), 0o600))
		args := append([]string{"evidence", "add-evidence", pkg}, order...)
		_, _, err := executeCommand(append(args, "--format", "raw-log")...)
		require.NoError(t, err, "order %v", order)
		refs := readEvidenceExternal(t, pkg)
		uris := make([]string, 0, len(refs))
		for _, r := range refs {
			uris = append(uris, r.(map[string]interface{})["uri"].(string))
		}
		assert.ElementsMatch(t, []string{"a.txt", "b.txt"}, uris, "order %v", order)
	}
}

// A literal duplicate is the operator's slip, refused by name before the package is
// read — never reported as an entry the package does not contain.
func TestEvidenceAddEvidence_LiteralDuplicateRefusedBeforePackageRead(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.WriteFile("a.txt", []byte("a"), 0o600))
	before, err := os.ReadFile(pkg)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--file", "a.txt", "--file", "./a.txt", "--format", "raw-log")
	require.Error(t, err)
	assert.ErrorContains(t, err, "selected twice")
	assert.ErrorContains(t, err, "--file")
	assert.NotContains(t, err.Error(), "already referenced")
	after, err := os.ReadFile(pkg)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// The never-the-package-itself rule holds for --uri exactly as for --file.
func TestEvidenceAddEvidence_URIToPackageRefused(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	before, err := os.ReadFile(pkg)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--uri", filepath.Base(pkg), "--format", "raw-log")
	require.Error(t, err)
	assert.ErrorContains(t, err, "package or output itself")
	after, err := os.ReadFile(pkg)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// A --uri naming the -o output is refused before any bytes are hashed, so an existing
// output is neither attested with a digest the write then invalidates nor overwritten.
func TestEvidenceAddEvidence_URIToOutputRefusedBeforeHash(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.WriteFile("out.json", []byte("stale output"), 0o600))
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", "out.json", "-o", "out.json", "--format", "raw-log")
	require.Error(t, err)
	assert.ErrorContains(t, err, "package or output itself")
	after, err := os.ReadFile("out.json")
	require.NoError(t, err)
	assert.Equal(t, "stale output", string(after), "the output must not be overwritten")
}

// The --format count rule has one implementation and one wording, whether the
// selectors are --uri only or mixed.
func TestEvidenceAddEvidence_FormatCountRuleHasOneWording(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.WriteFile("a.txt", []byte("a"), 0o600))
	for _, sel := range [][]string{
		{"--uri", "a.txt", "--uri", "b.txt"},
		{"--uri", "a.txt", "--file", "a.txt"},
	} {
		args := append([]string{"evidence", "add-evidence", pkg}, sel...)
		_, _, err := executeCommand(append(args, "--format", "raw-log", "--format", "x-a", "--format", "x-b")...)
		require.Error(t, err, "selectors %v", sel)
		assert.ErrorContains(t, err, "--uri, --file, --from-dir order", "selectors %v", sel)
	}
}

// ---- card hdf-libs-xfhfs.1: load-bearing tests ----

// A --from-dir root that cannot be resolved is refused with the directory named.
func TestEvidenceAddEvidence_FromDirRootLinkCycleRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges")
	}
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.Symlink("cycle", "cycle"))
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", "cycle", "--format", "raw-log")
	require.Error(t, err)
	assert.ErrorContains(t, err, "read evidence directory \"cycle\"")
	assert.Equal(t, 1, exitCodeOf(t, err))
}

// Without --no-follow-symlinks a --uri symlink is followed and the TARGET's bytes are
// attested — the default the flag exists to turn off.
func TestEvidenceAddEvidence_URISymlinkHashedWithoutFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges")
	}
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.WriteFile("in.log", []byte("target bytes"), 0o600))
	require.NoError(t, os.Symlink("in.log", "link.log"))
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--uri", "link.log", "--format", "raw-log")
	require.NoError(t, err)
	refs := readEvidenceExternal(t, pkg)
	require.Len(t, refs, 1)
	ref := refs[0].(map[string]interface{})
	assert.Equal(t, "link.log", ref["uri"])
	assert.Equal(t, map[string]interface{}{"algorithm": evidenceDigestAlgo, "value": evidenceDigestHex([]byte("target bytes"))}, ref["checksum"])
}

// Every DISTINCT format is validated, not only the first: a batch whose second value is
// invalid is refused, and nothing is written.
func TestEvidenceAddEvidence_EachDistinctFormatValidated(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.WriteFile("a.txt", []byte("a"), 0o600))
	require.NoError(t, os.WriteFile("b.txt", []byte("b"), 0o600))
	before, err := os.ReadFile(pkg)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "add-evidence", pkg, "--file", "a.txt", "--file", "b.txt", "--format", "raw-log", "--format", "x-Not-Lower")
	require.Error(t, err)
	assert.ErrorContains(t, err, "x-Not-Lower")
	assert.ErrorContains(t, err, "not valid")
	after, err := os.ReadFile(pkg)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}
