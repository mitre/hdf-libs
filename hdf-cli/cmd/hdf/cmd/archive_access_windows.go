//go:build windows

package cmd

import "os"

// openStagedArchive creates the staged archive as before the access policy existed;
// a protected creator-only DACL replaces this for private.
func openStagedArchive(path string, _ archiveAccess) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
}
