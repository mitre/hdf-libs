//go:build unix && !linux && !darwin

package cmd

import "os"

// createPrivateFile creates the staged archive exclusively with mode 0600.
func createPrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
}

// platformPrivateCheck adds nothing to the owner and mode read-back here: this
// platform's ACL inheritance (FreeBSD's NFSv4 ACLs, for one) is not checked.
func platformPrivateCheck(*os.File) error { return nil }
