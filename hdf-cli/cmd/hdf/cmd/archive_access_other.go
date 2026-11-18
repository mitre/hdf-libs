//go:build !linux && !darwin && !windows

package cmd

import (
	"errors"
	"os"
)

// openPrivateArchive refuses here: this platform's ACL model (FreeBSD's NFSv4 ACLs,
// for one) is not checked, so owner-only access cannot be established.
func openPrivateArchive(string) (*os.File, error) {
	return nil, errors.New("cannot create a private archive on this platform; " +
		"pass --output-access inherit if the destination's access policy is trusted")
}
