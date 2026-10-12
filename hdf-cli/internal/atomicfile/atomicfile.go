// Package atomicfile writes a file by staging it beside the destination and
// renaming it into place, so a crash, a full disk or a kill mid-write leaves the
// destination either wholly old or wholly new. The CLI's in-place commands write
// the user's own input file, where a truncate-then-write would destroy it.
//
// On Windows a write FAILS while another process holds the destination open:
// os.Rename is MoveFileEx(MOVEFILE_REPLACE_EXISTING), which must delete the
// destination, and a handle opened without FILE_SHARE_DELETE (what Go's own
// os.Open requests, and the common case for other readers) refuses that. The
// destination keeps its complete previous content and the caller gets the error
// — where a truncate-in-place would have succeeded. Windows also has no Unix
// mode bits, so the mode handling below is a no-op there.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile writes data to name atomically. perm is the mode for a destination
// that does not exist yet; an existing destination keeps its own permission
// bits, because the rename installs a new inode and would otherwise
// re-permission the user's file.
//
// The staged file is created in the destination's own directory: a rename cannot
// cross filesystems, so staging in the system temp directory would fail wherever
// the two differ. A directory that cannot hold the staged file therefore fails
// the write rather than falling back to an in-place truncate, which is the
// corruption this package exists to prevent.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	target := resolveDestination(name)
	if info, err := os.Stat(target); err == nil {
		perm = info.Mode().Perm()
	}

	staged, err := stageBeside(target, data, perm)
	if err != nil {
		return fmt.Errorf("staging an atomic write to %s: %w", name, err)
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("replacing %s with the staged write: %w", name, err)
	}
	return nil
}

// stageBeside creates the staged file in target's own directory, fills it, and
// returns its path. The only cleanup left to the caller is a rename that did not
// take.
func stageBeside(target string, data []byte, perm os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".tmp")
	if err != nil {
		return "", err
	}
	if err := stageTempFile(f, data, perm); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// stageTempFile fills the staged file and closes it, removing it if any step
// fails so a failure never leaves a partial file beside the destination. The
// fsync is what makes the subsequent rename durable as well as atomic: without
// it the rename can land while the data behind it is still only in the page
// cache.
func stageTempFile(f *os.File, data []byte, perm os.FileMode) error {
	fill := func() error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		if err := f.Chmod(perm); err != nil {
			return err
		}
		return f.Sync()
	}
	if err := fill(); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return nil
}

// resolveDestination follows a symlinked destination to the file it names, so
// the write lands on that file — as os.WriteFile's does — instead of replacing
// the link with a regular file, and so the staged file shares a filesystem with
// what is actually being replaced. A path that does not resolve (most often
// because it does not exist yet) is used as given.
func resolveDestination(name string) string {
	if resolved, err := filepath.EvalSymlinks(name); err == nil {
		return resolved
	}
	return name
}
