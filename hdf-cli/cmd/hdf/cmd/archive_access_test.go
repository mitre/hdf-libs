package cmd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArchiveAccessWindowsExtendedNames(t *testing.T) {
	for _, prefix := range []string{`\??\C:\`, `\\?\C:\`, `//?/C:/`, `\\?\UNC\server\share\`} {
		t.Run(prefix, func(t *testing.T) {
			path := prefix + strings.Repeat(`directory\`, 30) + "archive.zip"
			got, err := archiveWindowsName(path, func(string) (string, error) {
				return "", fmt.Errorf("extended names must bypass Win32 full-path interpretation")
			})
			require.NoError(t, err)
			require.Equal(t, path, got)
		})
	}
}

func TestArchiveAccessWindowsOrdinaryNames(t *testing.T) {
	longSuffix := strings.Repeat(`directory\`, 30) + "archive.zip"
	for _, tc := range []struct{ name, resolved, want string }{
		{"short", `C:\dir\archive.zip`, `C:\dir\archive.zip`},
		{"long-drive", `C:\` + longSuffix, `\\?\C:\` + longSuffix},
		{"long-unc", `\\server\share\` + longSuffix, `\\?\UNC\server\share\` + longSuffix},
		{"device", `\\.\C:\` + longSuffix, `\\.\C:\` + longSuffix},
		{"resolved-extended", `\\?\C:\` + longSuffix, `\\?\C:\` + longSuffix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			got, err := archiveWindowsName("archive.zip", func(path string) (string, error) {
				called = true
				require.Equal(t, "archive.zip", path)
				return tc.resolved, nil
			})
			require.NoError(t, err)
			require.True(t, called)
			require.Equal(t, tc.want, got)
		})
	}
	resolutionError := errors.New("path resolution failed")
	got, err := archiveWindowsName("archive.zip", func(string) (string, error) {
		return "", resolutionError
	})
	require.ErrorIs(t, err, resolutionError)
	require.Empty(t, got)
}
