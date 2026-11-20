//go:build unix && !linux && !darwin

package cmd

import (
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace has no exclusive rename to call here, so it answers ENOSYS as a
// rename error and publication uses the hard link, which refuses an existing name.
func renameNoReplace(oldpath, newpath string) error {
	return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: unix.ENOSYS}
}
