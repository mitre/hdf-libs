package atomicfile

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dirEntries returns the names in dir, so a test can assert no temporary file
// was left behind.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestWriteFile_CreatesFileWithRequestedMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports a synthesized mode (0666, or 0444 when read-only) instead of the requested bits, so there is nothing to assert; the content and no-stray-temp halves are covered by TestWriteFile_EmptyData and TestWriteFile_RemovesTempOnRenameFailure, and the mode is covered on unix")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "out.json")

	require.NoError(t, WriteFile(target, []byte("{\"a\":1}\n"), 0o600))

	got, err := os.ReadFile(target) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	assert.Equal(t, "{\"a\":1}\n", string(got))
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
	assert.Equal(t, []string{"out.json"}, dirEntries(t, dir), "no temporary file may survive a successful write")
}

func TestWriteFile_EmptyData(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "empty.json")

	require.NoError(t, WriteFile(target, nil, 0o600))

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())
}

// An in-place rewrite replaces the content but must not silently re-permission
// the user's file: the rename installs a new inode, so the mode is carried over
// deliberately.
func TestWriteFile_PreservesExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix mode bits for the rename to carry over — os.Chmod only toggles the read-only attribute — so the preservation this asserts is unix-only; the content replacement is covered OS-agnostically by TestWriteFile_OpenReaderSeesOneCompleteVersion")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "doc.json")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))
	require.NoError(t, os.Chmod(target, 0o640))

	require.NoError(t, WriteFile(target, []byte("new"), 0o600))

	got, err := os.ReadFile(target) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o640), info.Mode().Perm())
}

// The destination's bytes are the user's input for the in-place commands, so a
// write that cannot even begin must leave them exactly as they were.
func TestWriteFile_LeavesDestinationUntouchedOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ignores the 0o500 dir mode, so the staged file is created and the write is not denied; the same leave-nothing-behind property is covered OS-agnostically by TestWriteFile_RemovesTempOnRenameFailure")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory write permissions")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "doc.json")
	require.NoError(t, os.WriteFile(target, []byte("original bytes"), 0o600))
	require.NoError(t, os.Chmod(dir, 0o500)) // no write permission: no temp file can be created
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := WriteFile(target, []byte("replacement"), 0o600)

	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrPermission)
	got, readErr := os.ReadFile(target) // #nosec G304 -- test-controlled path
	require.NoError(t, readErr)
	assert.Equal(t, "original bytes", string(got))
	assert.Equal(t, []string{"doc.json"}, dirEntries(t, dir), "a failed write must leave no temporary file")
}

// A rename that cannot complete must not leave the half-written temp file
// sitting next to the destination.
func TestWriteFile_RemovesTempOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "occupied")
	require.NoError(t, os.Mkdir(target, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(target, "child"), []byte("x"), 0o600))

	err := WriteFile(target, []byte("replacement"), 0o600)

	require.Error(t, err)
	assert.Equal(t, []string{"occupied"}, dirEntries(t, dir), "a failed rename must leave no temporary file")
	assert.Equal(t, []string{"child"}, dirEntries(t, target), "the destination directory must be untouched")
}

func TestWriteFile_MissingParentDirectory(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nope", "out.json")

	err := WriteFile(target, []byte("x"), 0o600)

	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// os.WriteFile writes through a symlinked destination, so the atomic
// replacement resolves the link first: replacing the link itself would silently
// detach a file the user deliberately pointed elsewhere.
func TestWriteFile_WritesThroughSymlinkedDestination(t *testing.T) {
	store := t.TempDir()
	stored := filepath.Join(store, "real.json")
	require.NoError(t, os.WriteFile(stored, []byte("old"), 0o600))
	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "doc.json")
	require.NoError(t, os.Symlink(stored, link))

	require.NoError(t, WriteFile(link, []byte("new"), 0o600))

	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "the symlink must survive the write")
	got, err := os.ReadFile(stored) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
	assert.Equal(t, []string{"doc.json"}, dirEntries(t, linkDir))
	assert.Equal(t, []string{"real.json"}, dirEntries(t, store), "the temp file belongs beside the resolved file")
}

// A reader holding the destination open across the write gets one complete
// version, deterministically — and the two platforms get there differently, so
// each is asserted for what it actually does rather than for a shared guarantee
// only one of them offers.
func TestWriteFile_OpenReaderSeesOneCompleteVersion(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "doc.json")
	oldContent := []byte("old")
	newContent := bytes.Repeat([]byte("n"), 1<<20)
	require.NoError(t, os.WriteFile(target, oldContent, 0o600))

	reader, err := os.Open(target) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	writeErr := WriteFile(target, newContent, 0o600)

	if runtime.GOOS == "windows" {
		// os.Rename is MoveFileEx(MOVEFILE_REPLACE_EXISTING), which must delete
		// the destination, and Go opens files without FILE_SHARE_DELETE — so an
		// open reader makes the replacement fail instead of tear. The caller
		// sees the error and the destination keeps its complete old content.
		require.Error(t, writeErr)
		onDisk, readErr := os.ReadFile(target) // #nosec G304 -- test-controlled path
		require.NoError(t, readErr)
		assert.Equal(t, string(oldContent), string(onDisk), "a refused replacement must leave the old version complete")
		assert.Equal(t, []string{"doc.json"}, dirEntries(t, dir), "a refused replacement must leave no staged file")
		return
	}

	require.NoError(t, writeErr)
	held, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, string(oldContent), string(held), "the handle opened before the write keeps reading the complete old version")
	fresh, err := os.ReadFile(target) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	assert.Len(t, fresh, len(newContent), "a handle opened after the write sees the complete new version")
	assert.Equal(t, []string{"doc.json"}, dirEntries(t, dir))
}

// A reader repeatedly opening the destination while it is replaced never sees a
// truncated file — the property truncate-then-write cannot offer, and the one
// most real consumers exercise (open, read, close in a loop).
func TestWriteFile_ReaderSeesOneCompleteVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows the replacement is refused whenever the reader's handle happens to be open (MoveFileEx needs FILE_SHARE_DELETE), so whether this write succeeds is a race rather than a guarantee; the Windows outcome is asserted deterministically by TestWriteFile_OpenReaderSeesOneCompleteVersion")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "doc.json")
	oldContent := []byte("old")
	newContent := bytes.Repeat([]byte("n"), 1<<20)
	require.NoError(t, os.WriteFile(target, oldContent, 0o600))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			got, err := os.ReadFile(target) // #nosec G304 -- test-controlled path
			if err != nil {
				continue
			}
			if len(got) != len(oldContent) && len(got) != len(newContent) {
				t.Errorf("reader saw a partial file of %d bytes", len(got))
				return
			}
		}
	}()
	require.NoError(t, WriteFile(target, newContent, 0o600))
	<-done

	got, err := os.ReadFile(target) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	assert.Len(t, got, len(newContent))
}

// A write that fails partway through is reported rather than swallowed, and the
// staged file it was filling is removed instead of being left beside the
// destination.
func TestStageTempFile_ReportsAWriteFailureAndRemovesTheStagedFile(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "staged")
	require.NoError(t, err)
	require.NoError(t, f.Close()) // a closed handle fails every subsequent write

	err = stageTempFile(f, []byte("payload"), 0o600)

	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrClosed)
	assert.Empty(t, dirEntries(t, dir), "the staged file must not survive a failed write")
}
