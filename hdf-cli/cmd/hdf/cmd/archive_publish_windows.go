//go:build windows

package cmd

import (
	"os"

	"golang.org/x/sys/windows"
)

// renameNoReplace moves oldpath to newpath without MOVEFILE_REPLACE_EXISTING, so it
// fails with ERROR_ALREADY_EXISTS (fs.ErrExist) if newpath exists. Write-through makes
// the move durable before it returns, which is what a directory fsync does on unix.
// Both names get the long-path form creation gave CreateFileW: raw MoveFileExW has no
// long-path handling either.
func renameNoReplace(oldpath, newpath string) error {
	from, err := windowsNamePtr(oldpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	to, err := windowsNamePtr(newpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

// windowsNamePtr is path in the form raw Win32 file calls take: resolved, prefixed
// from 248 characters on, and UTF-16.
func windowsNamePtr(path string) (*uint16, error) {
	full, err := archiveWindowsName(path, windows.FullPath)
	if err != nil {
		return nil, err
	}
	return windows.UTF16PtrFromString(full)
}

// renameUnsupported is always false: MoveFileEx refuses an existing name on every
// filesystem, so Windows never needs the hard-link path.
func renameUnsupported(error) bool { return false }

// linkUnsupported is never reached on Windows; see renameUnsupported.
func linkUnsupported(error) bool { return false }

// syncDir has nothing to do on Windows: the move was made with write-through.
func syncDir(string) error { return nil }
