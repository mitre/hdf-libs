//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The staged archive is created before the source is read, so a destination that
// cannot take one is refused first. The source is missing here: reading it first would
// report that instead.
func TestConvertBundle_StagesTheArchiveBeforeReadingTheSource(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root creates files in a read-only directory")
	}
	dir := t.TempDir()
	sealed := filepath.Join(dir, "sealed")
	require.NoError(t, os.Mkdir(sealed, 0o500))
	out := filepath.Join(sealed, "export.zip")
	missing := filepath.Join(dir, "missing.json")

	_, _, err := executeCommand("convert", "--bundle", missing, "--to", "ecs", "-o", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-o "+out, "the destination is refused")
	assert.NotContains(t, err.Error(), "missing.json", "before the source is read")
}

// --output-access selects the staged file's creation policy: private is owner-only,
// inherit is 0666 under the process umask.
func TestConvertBundle_OutputAccessSetsTheArchiveMode(t *testing.T) {
	umask := syscall.Umask(0)
	syscall.Umask(umask)
	input := bundleSourceFixture(t)
	for _, tc := range []struct {
		access string
		want   os.FileMode
	}{
		{"private", 0o600},
		{"inherit", 0o666 &^ os.FileMode(umask)},
	} {
		t.Run(tc.access, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "export.zip")
			_, _, err := executeCommand("convert", "--bundle", input, "--to", "ecs", "-o", out,
				"--output-access", tc.access)
			require.NoError(t, err)
			info, err := os.Stat(out)
			require.NoError(t, err)
			assert.Equal(t, tc.want, info.Mode().Perm())
		})
	}
}
