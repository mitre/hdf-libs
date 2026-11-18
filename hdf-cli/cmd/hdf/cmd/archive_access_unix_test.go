//go:build linux || darwin

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inherit leaves the archive's mode to the umask (and the directory's default ACLs);
// private makes it owner-only. The bytes are the same either way.
func TestEvidenceBundleInheritAccess(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	dir, pkgPath := bundleTree(t)
	private := filepath.Join(dir, "private.zip")
	inherited := filepath.Join(dir, "inherited.zip")

	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", private)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", inherited, "--output-access", "inherit")
	require.NoError(t, err)

	privateInfo, err := os.Stat(private)
	require.NoError(t, err)
	inheritedInfo, err := os.Stat(inherited)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), privateInfo.Mode().Perm(), "private is owner-only")
	assert.Equal(t, os.FileMode(0o644), inheritedInfo.Mode().Perm(), "inherit is 0666 under the umask")

	privateBytes, err := os.ReadFile(private)
	require.NoError(t, err)
	inheritedBytes, err := os.ReadFile(inherited)
	require.NoError(t, err)
	assert.Equal(t, privateBytes, inheritedBytes, "the policy changes access, never content")
}

func fakeOwnerMode(uid int, mode uint32) func(*os.File) (uint32, uint32, error) {
	return func(*os.File) (uint32, uint32, error) { return uint32(uid), mode, nil }
}

// A filesystem whose mode bits do not reflect access reads back something other than
// owner-only after a 0600 create; that is refused, never trusted.
func TestArchiveAccess_PrivateRefusesAReadbackThatIsNotOwnerOnly(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "staged")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	me := os.Geteuid()

	require.NoError(t, verifyOwnerOnly(f, fakeOwnerMode(me, 0o100600)))
	for name, stat := range map[string]func(*os.File) (uint32, uint32, error){
		"group-readable (default SMB mount)": fakeOwnerMode(me, 0o100755),
		"world-readable (a FAT mount mask)":  fakeOwnerMode(me, 0o100777),
		"owned by someone else":              fakeOwnerMode(me+1, 0o100600),
	} {
		t.Run(name, func(t *testing.T) {
			err := verifyOwnerOnly(f, stat)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--output-access inherit", "the refusal names the deliberate alternative")
		})
	}
}

// A refused private creation leaves nothing behind: the staged file is removed.
func TestArchiveAccess_RefusedPrivateCreationRemovesTheStagedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), stagedArchivePrefix+"test")
	f, err := openPrivateArchiveWith(path, fakeOwnerMode(os.Geteuid(), 0o100755))
	require.Error(t, err)
	assert.Nil(t, f)
	assert.NoFileExists(t, path, "the staged file is removed")
}
