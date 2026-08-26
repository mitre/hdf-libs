package hdfutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The confinement INVARIANT is asserted (rejected-outside-base /
// resolves-inside-base / symlink-escape-rejected), not OS-specific literal
// path strings — separators and cleaning differ across platforms.

func TestSafePath_TraversalDenied(t *testing.T) {
	base := t.TempDir()

	// (a) a ../ escape relative to the base is rejected.
	if _, err := SafePath(base, "../outside.json"); err == nil {
		t.Fatal("expected error for ../ traversal escape")
	}

	// (b) an in-root relative path resolves to the expected absolute path.
	got, err := SafePath(base, "subdir/file.json")
	if err != nil {
		t.Fatalf("unexpected error for in-root path: %v", err)
	}
	if want := filepath.Join(base, "subdir", "file.json"); got != want {
		t.Errorf("in-root path: got %q, want %q", got, want)
	}

	// (c) a symlink inside the base that resolves outside it is rejected.
	outside := t.TempDir()
	link := filepath.Join(base, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	if _, err := SafePath(base, "escape/secret.json"); err == nil {
		t.Fatal("expected error for symlink escaping the base")
	}
}

func TestSafePath_ValidRelative(t *testing.T) {
	base := t.TempDir()
	got, err := SafePath(base, "subdir/file.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := filepath.Join(base, "subdir", "file.json"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSafePath_ValidBasename(t *testing.T) {
	base := t.TempDir()
	got, err := SafePath(base, "file.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := filepath.Join(base, "file.json"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSafePath_DeepTraversalBlocked(t *testing.T) {
	base := t.TempDir()
	if _, err := SafePath(base, "subdir/../../outside.json"); err == nil {
		t.Fatal("expected error for deep traversal")
	}
}

func TestSafePath_EmptyPathBlocked(t *testing.T) {
	base := t.TempDir()
	if _, err := SafePath(base, ""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestSafePath_DotResolvesToBase(t *testing.T) {
	base := t.TempDir()
	got, err := SafePath(base, ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := filepath.Clean(base); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// An in-root symlink that resolves back inside the base is allowed — the check
// rejects escapes, not links per se.
func TestSafePath_InRootSymlinkAllowed(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	got, err := SafePath(base, "link/file.json")
	if err != nil {
		t.Fatalf("unexpected error for in-root symlink: %v", err)
	}
	if want := filepath.Join(base, "link", "file.json"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A symlinked base directory (e.g. macOS /var -> /private/var under t.TempDir)
// must not be mistaken for an escape.
func TestSafePath_SymlinkedBaseNotEscape(t *testing.T) {
	realDir := t.TempDir()
	linkedBase := filepath.Join(t.TempDir(), "base")
	if err := os.Symlink(realDir, linkedBase); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	got, err := SafePath(linkedBase, "file.json")
	if err != nil {
		t.Fatalf("unexpected error for symlinked base: %v", err)
	}
	if !strings.HasPrefix(got, filepath.Clean(linkedBase)) {
		t.Errorf("returned path %q should stay under the caller-supplied base %q", got, linkedBase)
	}
}

// A path that descends through a regular-file component is rejected: resolving
// it yields a not-a-directory error rather than a plain not-exist.
func TestSafePath_ThroughFileComponentRejected(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "afile"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := SafePath(base, "afile/child.json"); err == nil {
		t.Fatal("expected error descending through a regular file")
	}
}

func TestSafePath_NonexistentBaseRejected(t *testing.T) {
	base := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := SafePath(base, "file.json"); err == nil {
		t.Fatal("expected error when the base directory cannot be resolved")
	}
}
