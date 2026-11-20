package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Characterization: copyDir skips dotfiles at the ROOT only — .git/ from a cloned
// baseline stays behind, a nested dotfile travels — the rule hiddenName now carries.
func TestCopyDir_SkipsRootDotfilesOnly(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "copy")
	require.NoError(t, os.MkdirAll(filepath.Join(src, ".git", "objects"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(src, ".git", "objects", "x"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, ".top"), []byte("t"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(src, "sub"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "sub", ".nested"), []byte("n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o600))
	require.NoError(t, copyDir(src, dst))
	assert.FileExists(t, filepath.Join(dst, "a.txt"))
	assert.FileExists(t, filepath.Join(dst, "sub", ".nested"))
	assert.NoFileExists(t, filepath.Join(dst, ".top"))
	assert.NoDirExists(t, filepath.Join(dst, ".git"))
}
