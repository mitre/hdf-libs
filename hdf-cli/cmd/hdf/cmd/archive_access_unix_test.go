//go:build linux || darwin

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestArchiveAccessUnixCreationPolicy(t *testing.T) {
	previous := unix.Umask(0o027)
	defer unix.Umask(previous)
	for _, mask := range []int{0, 0o027, 0o077} {
		unix.Umask(mask)
		for _, access := range []archiveAccess{archivePrivate, archiveInherit} {
			t.Run(fmt.Sprintf("%s/%03o", access, mask), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "archive.zip")
				require.NoError(t, os.WriteFile(path, []byte("old archive"), 0o400))
				want := os.FileMode(0o600)
				if access == archiveInherit {
					want = os.FileMode(0o666 &^ mask)
				}
				called := false
				err := writeArchiveAtomically(path, []bundleEntry{{path: "source.json", data: []byte("source bytes")}}, func(file *os.File) archiveWriter {
					called = true
					info, err := file.Stat()
					require.NoError(t, err)
					require.Zero(t, info.Size())
					require.Equal(t, want, info.Mode().Perm(), "policy must apply before the writer sees the file")
					return newArchiveWriter(file)
				}, true, access)
				require.NoError(t, err)
				require.True(t, called)
				info, err := os.Stat(path)
				require.NoError(t, err)
				require.Equal(t, want, info.Mode().Perm(), "overwrite uses new-file policy, not old permissions")
				require.Equal(t, []byte("source bytes"), zipEntries(t, path)["source.json"])
				files, err := os.ReadDir(filepath.Dir(path))
				require.NoError(t, err)
				require.Len(t, files, 1, "staged name must be cleaned")
			})
		}
	}
}

func TestArchiveAccessUnixOwnerReadback(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "owner-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	require.NoError(t, verifyArchiveOwner(file, unix.Fstat))
	for _, fault := range []string{"owner", "group", "other", "query"} {
		t.Run(fault, func(t *testing.T) {
			err := verifyArchiveOwner(file, func(fd int, stat *unix.Stat_t) error {
				if err := unix.Fstat(fd, stat); err != nil {
					return err
				}
				switch fault {
				case "owner":
					stat.Uid++
				case "group":
					stat.Mode |= 0o040
				case "other":
					stat.Mode |= 0o004
				case "query":
					return unix.EIO
				}
				return nil
			})
			require.Error(t, err)
			if fault == "query" {
				require.ErrorIs(t, err, unix.EIO)
			}
		})
	}
}
