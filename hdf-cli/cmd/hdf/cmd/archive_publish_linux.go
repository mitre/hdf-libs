//go:build linux

package cmd

import (
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldpath to newpath and fails with EEXIST if newpath exists.
// A kernel or filesystem without RENAME_NOREPLACE answers EINVAL or ENOSYS.
func renameNoReplace(oldpath, newpath string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}
