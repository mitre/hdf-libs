//go:build darwin

package cmd

import (
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldpath to newpath and fails with EEXIST if newpath exists.
// A filesystem without RENAME_EXCL answers ENOTSUP (exFAT does).
func renameNoReplace(oldpath, newpath string) error {
	if err := unix.RenameatxNp(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_EXCL); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}
