//go:build unix && !linux && !darwin

package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// private here is the 0600 exclusive create and the owner-and-mode read-back; the
// platform check adds nothing, and a name already taken is refused.
func TestArchiveAccessOtherPrivateIsTheOwnerOnlyReadback(t *testing.T) {
	path := filepath.Join(t.TempDir(), stagedArchivePrefix+"test")
	f, err := openPrivateArchive(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	info, err := f.Stat()
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.NoError(t, platformPrivateCheck(f))

	_, err = createPrivateFile(path)
	assert.ErrorIs(t, err, fs.ErrExist)
}
