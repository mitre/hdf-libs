//go:build !linux && !darwin && !windows

package cmd

import (
	"errors"
	"os"
)

// openStagedArchive refuses private here: this platform's ACL model (FreeBSD's NFSv4
// ACLs, for one) is not checked, so owner-only access cannot be established.
func openStagedArchive(path string, access archiveAccess) (*os.File, error) {
	if access == archiveInherit {
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
	}
	return nil, errors.New("cannot create a private archive on this platform; " +
		"pass --output-access inherit if the destination's access policy is trusted")
}
