//go:build windows

package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Raw MoveFileExW gets no long-path handling from Go, so a staged archive past MAX_PATH
// is published through the \\?\ form of both names, and an existing name is still
// refused as fs.ErrExist with the file at it left as it was.
func TestNoClobberPublishWindowsLongPaths(t *testing.T) {
	deep := filepath.Join(t.TempDir(), strings.Repeat("d", 120), strings.Repeat("e", 120))
	require.NoError(t, os.MkdirAll(deep, 0o700))
	staged := filepath.Join(deep, stagedArchivePrefix+"test")
	out := filepath.Join(deep, "boe.zip")
	require.GreaterOrEqual(t, len(out), 260)
	require.NoError(t, os.WriteFile(staged, []byte("archive"), 0o600))

	require.NoError(t, renameNoReplace(staged, out))
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "archive", string(got))
	assert.NoFileExists(t, staged)

	require.NoError(t, os.WriteFile(staged, []byte("again"), 0o600))
	err = renameNoReplace(staged, out)
	require.ErrorIs(t, err, fs.ErrExist)
	var le *os.LinkError
	require.ErrorAs(t, err, &le)
	assert.Equal(t, "rename", le.Op)
	got, err = os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "archive", string(got), "the published archive is untouched")

	_, err = windowsNamePtr(deep + `\bad` + "\x00" + "name")
	assert.Error(t, err, "a NUL inside a name is refused")
}
