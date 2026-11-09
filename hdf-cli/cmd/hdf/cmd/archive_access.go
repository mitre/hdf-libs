package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func createArchiveTemp(dir string) (*os.File, error) {
	for range 10 {
		path := filepath.Join(dir, ".hdf-bundle-"+rand.Text())
		file, err := openPrivateArchive(path)
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
