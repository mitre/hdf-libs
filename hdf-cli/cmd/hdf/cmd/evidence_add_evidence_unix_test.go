//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addEvidenceDeadline bounds an add-evidence call so a --uri that blocks on open fails
// this test instead of hanging the suite. The call runs on its own goroutine and is
// never waited on past the deadline: a blocked open cannot be cancelled, so the only
// way to report it is to stop waiting. runEvidenceAddEvidence is called directly
// because a goroutine parked inside it must not be holding anything shared.
func addEvidenceDeadline(t *testing.T, pkg string, opts addEvidenceOpts) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- runEvidenceAddEvidence(pkg, opts) }()
	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("add-evidence did not return within 15s: it is blocked on the fifo")
		return nil
	}
}

// newFifoPackage writes an evidence package with a fifo beside it, and returns the
// package path plus the fifo's package-relative name.
func newFifoPackage(t *testing.T) (pkg, fifo string) {
	t.Helper()
	dir := t.TempDir()
	pkg = filepath.Join(dir, "evidence.json")
	require.NoError(t, os.WriteFile(pkg, []byte(testEvidencePackage), 0o600))
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.ndjson"), 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	return pkg, "pipe.ndjson"
}

// A fifo stats as a non-directory of size 0, so every guard up to the open admitted it
// and the open then blocked until a writer appeared — with no timeout. Demonstrated
// conclusively: a parked invocation woke when a writer was armed later, hashed that
// payload and wrote the package, recording a digest of bytes the operator never meant
// to attest. Refused before any open, on the hashing path and on --infer's content
// read alike.
func TestEvidenceAddEvidence_RefusesANonRegularURIBeforeOpeningIt(t *testing.T) {
	t.Run("the hashing path", func(t *testing.T) {
		pkg, fifo := newFifoPackage(t)
		err := addEvidenceDeadline(t, pkg, addEvidenceOpts{
			uris: []string{fifo}, formats: []string{"raw-log"}, recordCount: -1,
		})
		require.Error(t, err, "a fifo cannot be hashed into an attestation; it must be refused")
		assert.Contains(t, err.Error(), "named pipe", "the refusal must name what it found")
	})

	t.Run("the infer path", func(t *testing.T) {
		pkg, fifo := newFifoPackage(t)
		err := addEvidenceDeadline(t, pkg, addEvidenceOpts{
			uris: []string{fifo}, infer: true, recordCount: -1,
		})
		require.Error(t, err, "--infer reads the artifact's content, so it must refuse a fifo too")
		assert.Contains(t, err.Error(), "named pipe", "the refusal must name what it found")
	})

	// The operator supplied the digest, so nothing needs opening and the entry records
	// what they stated.
	t.Run("with a supplied checksum", func(t *testing.T) {
		pkg, fifo := newFifoPackage(t)
		err := addEvidenceDeadline(t, pkg, addEvidenceOpts{
			uris:        []string{fifo},
			formats:     []string{"raw-log"},
			checksum:    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			outputPath:  filepath.Join(filepath.Dir(pkg), "out.json"),
			recordCount: -1,
		})
		require.NoError(t, err, "a stated digest needs no read")
		ext := readEvidenceExternal(t, filepath.Join(filepath.Dir(pkg), "out.json"))
		require.Len(t, ext, 1)
		assert.Equal(t, fifo, ext[0].(map[string]interface{})["uri"])
	})
}
