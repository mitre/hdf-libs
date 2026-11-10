package cmd

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type archiveLinuxAPI struct {
	statfs func(int, *unix.Statfs_t) error
	stat   func(int, *unix.Stat_t) error
}

func openPrivateArchive(path string) (*os.File, error) {
	return openPrivateArchiveWithLinuxAPI(path, archiveLinuxAPI{unix.Fstatfs, unix.Fstat})
}

func openPrivateArchiveWithLinuxAPI(path string, api archiveLinuxAPI) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := verifyLinuxArchiveAccess(file, api); err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(path))
	}
	return file, nil
}

func verifyLinuxArchiveAccess(file *os.File, api archiveLinuxAPI) error {
	var filesystem unix.Statfs_t
	if err := api.statfs(int(file.Fd()), &filesystem); err != nil {
		return fmt.Errorf("query private archive filesystem: %w", err)
	}
	switch archiveLinuxFilesystemType(filesystem.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC - 1<<32, unix.TMPFS_MAGIC:
		return verifyArchiveOwner(file, api.stat)
	default:
		return fmt.Errorf("cannot establish private archive access on filesystem %#x; use supported local storage or --output-access inherit with a trusted destination", filesystem.Type)
	}
}

// Linux Statfs.Type is int32, int64 or uint32 depending on the architecture.
func archiveLinuxFilesystemType[T ~int32 | ~int64 | ~uint32](kind T) int64 {
	return int64(kind)
}
