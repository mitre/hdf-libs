//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mkfifo does not exist on Windows, so this lives behind the unix tag rather than a
// runtime skip: the symbol fails to COMPILE there, which takes the whole package with it.
// The scan funnelled every non-regular kind into one bucket and called them all
// symlinks, so a fifo was reported as a symlink and told to name its target —
// advice that means nothing for a pipe. nonRegularKind already names each kind.
func TestEvidenceBuild_FromDirNamesTheKindItSkipped(t *testing.T) {
	dir := scanTree(t)
	require.NoError(t, syscall.Mkfifo(filepath.Join(dir, "apipe"), 0o600))
	require.NoError(t, os.Symlink("system.json", filepath.Join(dir, "alink.json")))

	_, stderr, err := executeCommand("evidence", "build", "--from-dir", dir,
		"-o", filepath.Join(dir, "pkg.json"))
	require.NoError(t, err)

	var pipeLine, linkLine string
	for _, l := range strings.Split(stderr, "\n") {
		switch {
		case strings.Contains(l, "apipe"):
			pipeLine = l
		case strings.Contains(l, "alink.json"):
			linkLine = l
		}
	}
	require.NotEmpty(t, pipeLine, "the fifo must be reported, not dropped")
	require.NotEmpty(t, linkLine, "the symlink must be reported too")

	assert.Contains(t, pipeLine, "a named pipe", "a fifo must be named as one")
	assert.NotContains(t, pipeLine, "a symlink", "a fifo is not a symlink")
	// The advice is only true of a symlink, so it must travel with that kind alone.
	assert.NotContains(t, pipeLine, "Name its target",
		"a pipe has no target to name; that advice belongs to a symlink")

	assert.Contains(t, linkLine, "a symlink", "a symlink still says symlink")
	assert.Contains(t, linkLine, "Name its target", "and keeps its advice")
}
