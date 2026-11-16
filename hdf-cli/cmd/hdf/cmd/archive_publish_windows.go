//go:build windows

package cmd

import (
	"os"

	"golang.org/x/sys/windows"
)

// renameNoReplace moves oldpath to newpath without MOVEFILE_REPLACE_EXISTING, so it
// fails with ERROR_ALREADY_EXISTS (fs.ErrExist) if newpath exists. Write-through makes
// the move durable before it returns, which is what a directory fsync does on unix.
func renameNoReplace(oldpath, newpath string) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

// renameUnsupported is always false: MoveFileEx refuses an existing name on every
// filesystem, so Windows never needs the hard-link path.
func renameUnsupported(error) bool { return false }

// linkUnsupported is never reached on Windows; see renameUnsupported.
func linkUnsupported(error) bool { return false }

// syncDir has nothing to do on Windows: the move was made with write-through.
func syncDir(string) error { return nil }
