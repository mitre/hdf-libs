//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func linkErr(op string, errno error) error {
	return &os.LinkError{Op: op, Old: "staged", New: "out", Err: errno}
}

// Each error a kernel or filesystem without the operation returns is recognized bare
// and wrapped in the *os.LinkError the callers return; EPERM is a missing link only.
func TestPublishPredicates_RecognizeAMissingOperation(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EINVAL, unix.ENOSYS, unix.ENOTSUP, unix.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			assert.True(t, renameUnsupported(errno))
			assert.True(t, renameUnsupported(linkErr("rename", errno)))
			assert.True(t, linkUnsupported(errno))
			assert.True(t, linkUnsupported(linkErr("link", errno)))
		})
	}
	assert.True(t, linkUnsupported(unix.EPERM), "link(2) on a filesystem without hard links")
	assert.True(t, linkUnsupported(linkErr("link", unix.EPERM)))
	assert.False(t, renameUnsupported(unix.EPERM), "a rename refused for permission is not retried as a link")
	assert.False(t, renameUnsupported(linkErr("rename", unix.EPERM)))
}

// Every other failure, an existing name above all, is neither predicate's.
func TestPublishPredicates_PassOtherFailuresThrough(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EEXIST, unix.EACCES, unix.ENOENT, unix.EXDEV, unix.ENOSPC, unix.EIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			assert.False(t, renameUnsupported(errno))
			assert.False(t, renameUnsupported(linkErr("rename", errno)))
			assert.False(t, linkUnsupported(errno))
			assert.False(t, linkUnsupported(linkErr("link", errno)))
		})
	}
	assert.False(t, renameUnsupported(nil))
	assert.False(t, linkUnsupported(nil))
}

// A filesystem that answers ENOSYS to the rename and the link alike (a FUSE server
// without hard links) gets the refusal that says what to do, not a bare write error.
func TestNoClobberPublish_ExplainsAFilesystemWithoutLinks(t *testing.T) {
	staged, out := publishFixture(t)
	nosys := func(op string) func(string, string) error {
		return func(oldpath, newpath string) error {
			return &os.LinkError{Op: op, Old: oldpath, New: newpath, Err: unix.ENOSYS}
		}
	}
	ops := platformNoClobber
	ops.rename, ops.link = nosys("rename"), nosys("link")

	err := ops.publish(staged, out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "can neither rename nor link")
	assert.Contains(t, err.Error(), "rename: "+unix.ENOSYS.Error())
	assert.Contains(t, err.Error(), "--overwrite")
	assert.NotContains(t, err.Error(), filepath.Base(staged))
	assert.NoFileExists(t, out)
}

// The platform's exclusive rename refuses an existing name with an error publication
// reads as fs.ErrExist, and leaves that file as it was.
func TestRenameNoReplace_RefusesAnExistingName(t *testing.T) {
	staged, out := publishFixture(t)
	require.NoError(t, os.WriteFile(out, []byte("theirs"), 0o600))

	err := renameNoReplace(staged, out)
	if renameUnsupported(err) {
		t.Skip("this platform has no exclusive rename; publication links instead")
	}
	require.ErrorIs(t, err, os.ErrExist)
	var le *os.LinkError
	require.ErrorAs(t, err, &le)
	assert.Equal(t, "rename", le.Op)
	got, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	assert.Equal(t, "theirs", string(got))
	assert.FileExists(t, staged)
}
