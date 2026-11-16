package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// archiveAccess is who may read the archive bundle writes: its creator alone
// (private), or whoever the directory's umask and default ACLs admit (inherit).
type archiveAccess string

const (
	archivePrivate archiveAccess = "private"
	archiveInherit archiveAccess = "inherit"
)

// parseArchiveAccess accepts exactly the two policy names, so a typo or a case
// variant never silently selects one.
func parseArchiveAccess(value string) (archiveAccess, error) {
	switch archiveAccess(value) {
	case archivePrivate, archiveInherit:
		return archiveAccess(value), nil
	default:
		return "", fmt.Errorf("--output-access must be private or inherit, got %q", value)
	}
}

// createStagedArchive creates the staged archive beside the destination under the
// access policy, establishing that access before any byte is written.
func createStagedArchive(dir string, access archiveAccess) (*os.File, error) {
	return createStagedArchiveWith(dir, access, openStagedArchive)
}

// createStagedArchiveWith takes the opener so a test can drive the name loop and the
// failure paths without a filesystem that misbehaves.
func createStagedArchiveWith(dir string, access archiveAccess,
	open func(path string, access archiveAccess) (*os.File, error)) (*os.File, error) {
	for range 10 {
		f, err := open(filepath.Join(dir, ".hdf-bundle-"+rand.Text()), access)
		if os.IsExist(err) {
			continue
		}
		return f, err
	}
	return nil, fmt.Errorf("cannot allocate a unique staged archive name in %s: %w", dir, os.ErrExist)
}
