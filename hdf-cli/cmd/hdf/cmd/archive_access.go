package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type archiveAccess string

const (
	archivePrivate archiveAccess = "private"
	archiveInherit archiveAccess = "inherit"
)

func archiveAccessFlag(cmd *cobra.Command) (archiveAccess, error) {
	value, err := cmd.Flags().GetString("output-access")
	if err != nil {
		return "", err
	}
	switch value {
	case string(archivePrivate):
		return archivePrivate, nil
	case string(archiveInherit):
		return archiveInherit, nil
	default:
		return "", fmt.Errorf("--output-access must be private or inherit, got %q", value)
	}
}

func createArchiveTemp(dir string, access archiveAccess) (*os.File, error) {
	return createArchiveTempWithOpener(dir, access, openArchive)
}

func openArchive(path string, access archiveAccess) (*os.File, error) {
	switch access {
	case archivePrivate:
		return openPrivateArchive(path)
	case archiveInherit:
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
	default:
		return nil, fmt.Errorf("invalid archive access policy %q", access)
	}
}

func createArchiveTempWithOpener(dir string, access archiveAccess, open func(string, archiveAccess) (*os.File, error)) (*os.File, error) {
	for range 10 {
		path := filepath.Join(dir, ".hdf-bundle-"+rand.Text())
		file, err := open(path, access)
		if os.IsExist(err) {
			continue
		}
		return file, err
	}
	return nil, fmt.Errorf("cannot allocate a unique archive file: %w", os.ErrExist)
}

func archiveWindowsName(path string, fullPath func(string) (string, error)) (string, error) {
	if strings.HasPrefix(path, `\??\`) || strings.HasPrefix(strings.ReplaceAll(path, "/", `\`), `\\?\`) {
		return path, nil
	}
	full, err := fullPath(path)
	if err != nil {
		return "", err
	}
	// Raw CreateFile does not receive Go's automatic long-path expansion.
	if len(full) >= 248 && !strings.HasPrefix(full, `\\?\`) && !strings.HasPrefix(full, `\\.\`) {
		if strings.HasPrefix(full, `\\`) {
			full = `\\?\UNC\` + strings.TrimPrefix(full, `\\`)
		} else {
			full = `\\?\` + full
		}
	}
	return full, nil
}
