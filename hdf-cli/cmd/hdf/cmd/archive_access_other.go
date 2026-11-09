//go:build !windows

package cmd

import "os"

func openPrivateArchive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
}
