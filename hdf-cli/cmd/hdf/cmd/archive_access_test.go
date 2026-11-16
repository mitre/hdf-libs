package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Only the two policy names are accepted, and a wrong one is refused before the
// package is read: the package path here does not exist, so reaching the read would
// report that instead.
func TestArchiveAccess_RejectsAnythingButPrivateOrInherit(t *testing.T) {
	for _, value := range []string{"", "Private", "INHERIT", "public", "0600"} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "boe.zip")
			_, _, err := executeCommand("evidence", "bundle", filepath.Join(dir, "missing.json"),
				"-o", out, "--output-access", value)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--output-access must be private or inherit")
			entries, readErr := os.ReadDir(dir)
			require.NoError(t, readErr)
			assert.Empty(t, entries, "no staged file and no output")
		})
	}
}

// The Windows name for CreateFileW follows Go's own os package: a path already in the
// extended namespace is used as given, and a resolved path of 248 characters or more
// gets the \\?\ prefix (\\?\UNC\ for a share), since raw CreateFileW does not get
// Go's long-path handling. A device path keeps its meaning.
func TestArchiveAccess_WindowsNameKeepsExtendedPaths(t *testing.T) {
	long := strings.Repeat(`directory\`, 30) + "archive.zip"
	for _, prefix := range []string{`\??\C:\`, `\\?\C:\`, `//?/C:/`, `\/?\C:\`, `\\?\UNC\server\share\`} {
		t.Run(prefix, func(t *testing.T) {
			got, err := archiveWindowsName(prefix+long, func(string) (string, error) {
				return "", errors.New("an extended path must not be resolved")
			})
			require.NoError(t, err)
			assert.Equal(t, prefix+long, got)
		})
	}
}

func TestArchiveAccess_WindowsNamePrefixesLongResolvedPaths(t *testing.T) {
	long := strings.Repeat(`directory\`, 30) + "archive.zip"
	under := `C:\` + strings.Repeat("a", 247-len(`C:\`))
	at := `C:\` + strings.Repeat("a", 248-len(`C:\`))
	for _, tc := range []struct{ name, resolved, want string }{
		{"short drive path", `C:\dir\archive.zip`, `C:\dir\archive.zip`},
		{"247 characters", under, under},
		{"248 characters", at, `\\?\` + at},
		{"long drive path", `C:\` + long, `\\?\C:\` + long},
		{"long share path", `\\server\share\` + long, `\\?\UNC\server\share\` + long},
		{"long device path", `\\.\C:\` + long, `\\.\C:\` + long},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := archiveWindowsName("C:/dir/archive.zip", func(path string) (string, error) {
				assert.Equal(t, "C:/dir/archive.zip", path, "the given path is what gets resolved")
				return tc.resolved, nil
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	failure := errors.New("cannot resolve")
	_, err := archiveWindowsName("archive.zip", func(string) (string, error) { return "", failure })
	assert.ErrorIs(t, err, failure)
}
