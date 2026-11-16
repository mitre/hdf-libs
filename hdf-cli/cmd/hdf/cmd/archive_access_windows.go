//go:build windows

package cmd

import (
	"os"

	"golang.org/x/sys/windows"
)

func openStagedArchive(path string, access archiveAccess) (*os.File, error) {
	if access == archiveInherit {
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
	}
	return createPrivateWindows(path, volumeACLFlags)
}

func createPrivateWindows(path string, _ func(windows.Handle) (uint32, error)) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
}

func volumeACLFlags(windows.Handle) (uint32, error) { return windows.FILE_PERSISTENT_ACLS, nil }

func verifyPrivateDACL(windows.Handle, *windows.SID) error { return nil }
