//go:build darwin

package cmd

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldpath to newpath and fails with EEXIST if newpath exists.
func renameNoReplace(oldpath, newpath string) error {
	if err := unix.RenameatxNp(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_EXCL); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

// renameUnsupported reports the errors renameatx_np gives when the filesystem lacks
// RENAME_EXCL (exFAT returns ENOTSUP). Darwin's ENOTSUP and EOPNOTSUPP are distinct.
func renameUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS)
}
