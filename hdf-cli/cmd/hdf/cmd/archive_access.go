package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// archiveWindowsName returns the name to give CreateFileW, following Go's own
// os.addExtendedPrefix: raw CreateFileW does not get Go's long-path handling. A path
// already in the extended namespace is used as given; otherwise the resolved full
// path gets the \\?\ prefix (\\?\UNC\ for a share) from 248 characters on, the
// length at which Windows stops accepting a plain path. A \\.\ device path is never
// prefixed, since that would change what it names.
func archiveWindowsName(path string, fullPath func(string) (string, error)) (string, error) {
	if windowsExtendedPath(path) {
		return path, nil
	}
	full, err := fullPath(path)
	if err != nil {
		return "", err
	}
	switch {
	case len(full) < 248, strings.HasPrefix(full, `\\.\`):
		return full, nil
	case strings.HasPrefix(full, `\\`):
		return `\\?\UNC\` + full[2:], nil
	default:
		return `\\?\` + full, nil
	}
}

// windowsExtendedPath reports a path already in the extended namespace: \??\, or \\?\
// written with either separator.
func windowsExtendedPath(path string) bool {
	separator := func(c byte) bool { return c == '\\' || c == '/' }
	return strings.HasPrefix(path, `\??\`) ||
		len(path) >= 4 && separator(path[0]) && separator(path[1]) && path[2] == '?' && separator(path[3])
}
