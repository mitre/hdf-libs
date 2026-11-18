//go:build unix

package cmd

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// unsupportedErrnos are what a kernel or filesystem without an operation returns:
// ENOTSUP and EOPNOTSUPP (distinct values on macOS, where exFAT gives ENOTSUP),
// EINVAL for a rename flag the filesystem does not take, and ENOSYS for a call the
// kernel or a FUSE server does not implement.
var unsupportedErrnos = []error{unix.ENOTSUP, unix.EOPNOTSUPP, unix.EINVAL, unix.ENOSYS}

func isAnyOf(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// renameUnsupported reports an exclusive rename the kernel or filesystem lacks.
func renameUnsupported(err error) bool { return isAnyOf(err, unsupportedErrnos...) }

// linkUnsupported reports a hard link the filesystem lacks: the errors above, and the
// EPERM link(2) returns on Linux for a filesystem without hard links.
func linkUnsupported(err error) bool {
	return errors.Is(err, unix.EPERM) || isAnyOf(err, unsupportedErrnos...)
}

// syncDir flushes the directory entry a rename or link created, so the published
// name survives a crash. A filesystem that cannot sync a directory (EINVAL, ENOTSUP)
// offers no stronger guarantee to report.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil &&
		!errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EOPNOTSUPP) {
		return err
	}
	return nil
}
