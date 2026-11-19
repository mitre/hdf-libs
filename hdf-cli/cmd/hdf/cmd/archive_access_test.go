package cmd

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Only the two policy names are accepted, and a wrong one is refused before the
// package is read: the package path here does not exist, so reaching the read would
// report that instead.
func TestArchiveAccess_RejectsAnythingButPrivateOrInherit(t *testing.T) {
	for _, value := range []string{"", "Private", "INHERIT", "public", "0600"} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "boe.zip")
			_, _, err := executeCommand("evidence", "bundle", filepath.Join(dir, "missing.json"),
				"-o", out, "--output-access", value)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--output-access must be private or inherit")
			entries, readErr := os.ReadDir(dir)
			require.NoError(t, readErr)
			assert.Empty(t, entries, "no staged file and no output")
		})
	}
}

// The Windows name for CreateFileW follows Go's own os package: a path already in the
// extended namespace is used as given, and a resolved path of 248 characters or more
// gets the \\?\ prefix (\\?\UNC\ for a share), since raw CreateFileW does not get
// Go's long-path handling. A device path keeps its meaning.
func TestArchiveAccess_WindowsNameKeepsExtendedPaths(t *testing.T) {
	long := strings.Repeat(`directory\`, 30) + "archive.zip"
	for _, prefix := range []string{`\??\C:\`, `\\?\C:\`, `//?/C:/`, `\/?\C:\`, `\\?\UNC\server\share\`} {
		t.Run(prefix, func(t *testing.T) {
			got, err := archiveWindowsName(prefix+long, func(string) (string, error) {
				return "", errors.New("an extended path must not be resolved")
			})
			require.NoError(t, err)
			assert.Equal(t, prefix+long, got)
		})
	}
}

func TestArchiveAccess_WindowsNamePrefixesLongResolvedPaths(t *testing.T) {
	long := strings.Repeat(`directory\`, 30) + "archive.zip"
	under := `C:\` + strings.Repeat("a", 247-len(`C:\`))
	at := `C:\` + strings.Repeat("a", 248-len(`C:\`))
	for _, tc := range []struct{ name, resolved, want string }{
		{"short drive path", `C:\dir\archive.zip`, `C:\dir\archive.zip`},
		{"247 characters", under, under},
		{"248 characters", at, `\\?\` + at},
		{"long drive path", `C:\` + long, `\\?\C:\` + long},
		{"long share path", `\\server\share\` + long, `\\?\UNC\server\share\` + long},
		{"long device path", `\\.\C:\` + long, `\\.\C:\` + long},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := archiveWindowsName("C:/dir/archive.zip", func(path string) (string, error) {
				assert.Equal(t, "C:/dir/archive.zip", path, "the given path is what gets resolved")
				return tc.resolved, nil
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	failure := errors.New("cannot resolve")
	_, err := archiveWindowsName("archive.zip", func(string) (string, error) { return "", failure })
	assert.ErrorIs(t, err, failure)
}

func existsAt(path string) error { return &os.PathError{Op: "open", Path: path, Err: fs.ErrExist} }

// A staged name already taken is tried again under another name in the same directory,
// under the prefix, with the access policy asked for each time.
func TestCreateStagedArchive_RetriesATakenName(t *testing.T) {
	dir := t.TempDir()
	var names []string
	f, err := createStagedArchiveWith(dir, archivePrivate, func(path string, access archiveAccess) (*os.File, error) {
		names = append(names, path)
		assert.Equal(t, archivePrivate, access)
		if len(names) < 3 {
			return nil, existsAt(path)
		}
		return os.Create(path)
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	require.Len(t, names, 3, "two taken names, then the one that was free")
	seen := map[string]bool{}
	for _, name := range names {
		assert.Equal(t, dir, filepath.Dir(name))
		assert.True(t, strings.HasPrefix(filepath.Base(name), stagedArchivePrefix), name)
		seen[name] = true
	}
	assert.Len(t, seen, 3, "every attempt is a different name")
	assert.Equal(t, names[2], f.Name())
}

// Ten taken names in a row stop the loop with an error that names the directory and
// still reads as "exists", so nothing above retries it once more.
func TestCreateStagedArchive_GivesUpAfterTenTakenNames(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	f, err := createStagedArchiveWith(dir, archiveInherit, func(path string, _ archiveAccess) (*os.File, error) {
		calls++
		return nil, existsAt(path)
	})
	require.Error(t, err)
	assert.Nil(t, f)
	assert.Equal(t, 10, calls)
	assert.ErrorIs(t, err, fs.ErrExist)
	assert.Contains(t, err.Error(), "cannot allocate a unique staged archive name in "+dir)
	assert.NotContains(t, err.Error(), stagedArchivePrefix, "no attempted name is shown")
}

// Any other failure is returned as it is, after one attempt.
func TestCreateStagedArchive_ReturnsOtherFailuresAtOnce(t *testing.T) {
	calls := 0
	_, err := createStagedArchiveWith(t.TempDir(), archivePrivate, func(path string, _ archiveAccess) (*os.File, error) {
		calls++
		return nil, &os.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	})
	assert.ErrorIs(t, err, fs.ErrPermission)
	assert.Equal(t, 1, calls)
}

// The network-storage note is one line, naming the storage kind.
func TestNoteNetworkStorage_IsOneLineNamingTheStorage(t *testing.T) {
	var notes bytes.Buffer
	noteNetworkStorage(&notes, "NFS")
	assert.Equal(t, "Note: the archive is on NFS storage; "+
		"the server and its mount options also control who can read it.\n", notes.String())
}

// Discarding a refused staged file reports the refusal, and any failure to close or
// remove the file alongside it rather than instead of it.
func TestDiscardStaged_JoinsEveryFailureToTheCause(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "staged"))
	require.NoError(t, err)
	cause := errors.New("refused")

	err = discardStaged(f, f.Name(), cause)
	assert.ErrorIs(t, err, cause)
	assert.Equal(t, cause.Error(), err.Error(), "a clean discard reports the cause alone")
	assert.NoFileExists(t, f.Name())

	err = discardStaged(f, f.Name(), cause)
	assert.ErrorIs(t, err, cause)
	assert.ErrorIs(t, err, os.ErrClosed, "closing twice is reported")
	assert.ErrorIs(t, err, fs.ErrNotExist, "and so is removing twice")
}

// inherit is the same exclusive create on every platform; a name already taken is
// refused as fs.ErrExist and the file at it is left as it was.
func TestOpenStagedArchive_InheritRefusesAnExistingName(t *testing.T) {
	path := filepath.Join(t.TempDir(), stagedArchivePrefix+"taken")
	require.NoError(t, os.WriteFile(path, []byte("kept"), 0o600))
	f, err := openStagedArchive(path, archiveInherit)
	require.ErrorIs(t, err, fs.ErrExist)
	assert.Nil(t, f)
	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "kept", string(got))
}
