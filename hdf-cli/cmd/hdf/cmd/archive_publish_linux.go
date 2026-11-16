//go:build linux

package cmd

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldpath to newpath and fails with EEXIST if newpath exists.
func renameNoReplace(oldpath, newpath string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

// renameUnsupported reports the errors renameat2 gives when the kernel or the
// filesystem lacks RENAME_NOREPLACE (rename(2): EINVAL for an unsupported flag).
func renameUnsupported(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP)
}
