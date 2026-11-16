//go:build unix

package cmd

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// linkUnsupported reports the errors link(2) gives when the filesystem has no hard
// links: EPERM on Linux (link(2)), ENOTSUP on macOS exFAT and FAT.
func linkUnsupported(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL)
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
