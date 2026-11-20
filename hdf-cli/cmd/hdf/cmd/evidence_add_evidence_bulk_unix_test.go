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

// Mkfifo does not exist on Windows, so these live behind the unix tag. Both are
// characterization tests: the kind phrase comes from nonRegularKind on every path.
func TestEvidenceAddEvidence_FifoNamedByFileRefusedAsNamedPipe(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, syscall.Mkfifo("pipe.log", 0o600))
	_, _, err := executeCommand("evidence", "add-evidence", pkg, "--file", "pipe.log", "--format", "raw-log")
	require.Error(t, err)
	assert.ErrorContains(t, err, "is a named pipe")
	assert.Empty(t, readEvidenceExternal(t, pkg))
}

func TestEvidenceAddEvidence_FifoDiscoveredSkippedAsNamedPipe(t *testing.T) {
	pkg := writeTestEvidence(t)
	t.Chdir(filepath.Dir(pkg))
	require.NoError(t, os.Mkdir("ev", 0o700))
	require.NoError(t, syscall.Mkfifo(filepath.Join("ev", "pipe"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join("ev", "in.log"), []byte("in"), 0o600))
	_, stderr, err := executeCommand("evidence", "add-evidence", pkg, "--from-dir", "ev", "--format", "raw-log")
	require.NoError(t, err)
	assert.Contains(t, stderr, "Skipped ev/pipe: a named pipe")
	require.Len(t, readEvidenceExternal(t, pkg), 1)
}
