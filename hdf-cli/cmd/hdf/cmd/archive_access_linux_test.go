package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestArchiveAccessLinuxFilesystem(t *testing.T) {
	dir := t.TempDir()
	var filesystem unix.Statfs_t
	require.NoError(t, unix.Statfs(dir, &filesystem))
	path := filepath.Join(dir, "archive.zip")
	file, err := openPrivateArchive(path)
	if file != nil {
		t.Cleanup(func() { require.NoError(t, file.Close()) })
	}
	switch archiveLinuxFilesystemType(filesystem.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC - 1<<32, unix.TMPFS_MAGIC:
		require.NoError(t, err)
		require.NotNil(t, file)
		info, err := file.Stat()
		require.NoError(t, err)
		require.Zero(t, info.Size())
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	default:
		require.ErrorContains(t, err, "cannot establish private archive access")
		require.Nil(t, file)
		require.NoFileExists(t, path)
	}
}

func TestArchiveAccessLinuxRejectsReadback(t *testing.T) {
	for _, scenario := range []string{"group-read", "other-read", "owner", "stat-error", "filesystem-error", "unsupported-filesystem"} {
		t.Run(scenario, func(t *testing.T) {
			api := archiveLinuxAPI{
				statfs: func(_ int, stat *unix.Statfs_t) error {
					stat.Type = unix.TMPFS_MAGIC
					if scenario == "unsupported-filesystem" {
						stat.Type = unix.OVERLAYFS_SUPER_MAGIC
					}
					if scenario == "filesystem-error" {
						return unix.EIO
					}
					return nil
				},
				stat: func(fd int, stat *unix.Stat_t) error {
					if err := unix.Fstat(fd, stat); err != nil {
						return err
					}
					switch scenario {
					case "group-read":
						stat.Mode |= 0o040
					case "other-read":
						stat.Mode |= 0o004
					case "owner":
						stat.Uid++
					case "stat-error":
						return unix.EIO
					}
					return nil
				},
			}
			path := filepath.Join(t.TempDir(), "unverified.zip")
			file, err := openPrivateArchiveWithLinuxAPI(path, api)
			if file != nil {
				t.Cleanup(func() { require.NoError(t, file.Close()) })
			}
			require.Error(t, err)
			require.Nil(t, file)
			require.NoFileExists(t, path)
			if scenario == "stat-error" || scenario == "filesystem-error" {
				require.ErrorIs(t, err, unix.EIO)
			}
		})
	}
}

func TestArchiveAccessLinuxCreationErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.zip")
	original := []byte("preserve this archive")
	require.NoError(t, os.WriteFile(path, original, 0o600))
	file, err := openPrivateArchive(path)
	require.Nil(t, file)
	require.ErrorIs(t, err, os.ErrExist)
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, actual)
	file, err = openPrivateArchive(filepath.Join(t.TempDir(), "missing", "out.zip"))
	require.Nil(t, file)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestArchiveAccessLinuxBtrfsMagic(t *testing.T) {
	for _, shape := range []string{"native-width", "32-bit-pattern"} {
		t.Run(shape, func(t *testing.T) {
			api := archiveLinuxAPI{statfs: func(_ int, stat *unix.Statfs_t) error {
				// Assemble the value without a constant that overflows signed 32-bit fields.
				stat.Type = unix.BTRFS_SUPER_MAGIC >> 1
				stat.Type = stat.Type<<1 | unix.BTRFS_SUPER_MAGIC&1
				if shape == "32-bit-pattern" {
					// On signed fields, this also exercises the sign-extended 32-bit value.
					stat.Type = unix.BTRFS_SUPER_MAGIC ^ 0xffffffff
					stat.Type = ^stat.Type
				}
				return nil
			}, stat: unix.Fstat}
			file, err := openPrivateArchiveWithLinuxAPI(filepath.Join(t.TempDir(), "btrfs.zip"), api)
			require.NoError(t, err, "both Btrfs representations must be accepted")
			require.NoError(t, file.Close())
		})
	}
}
