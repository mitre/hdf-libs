package hdfutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SafePath joins baseDir and relPath and verifies the result stays confined
// within baseDir, rejecting both lexical "../" traversal escapes and symlink
// escapes (a link inside the base that resolves to a location outside it).
//
// baseDir is supplied explicitly by the caller — the helper reads no ambient
// state (cwd, environment); the MCP passes HDF_MCP_ROOT, the CLI passes its own
// base. The returned path is the lexically-cleaned join: symlinks are validated
// for containment, not expanded, so callers get a stable, predictable path.
func SafePath(baseDir, relPath string) (string, error) {
	if relPath == "" {
		return "", fmt.Errorf("empty path")
	}
	cleanBase := filepath.Clean(baseDir)
	resolved := filepath.Clean(filepath.Join(cleanBase, relPath))
	if !within(cleanBase, resolved) {
		return "", fmt.Errorf("path traversal detected: %q resolves outside base directory", relPath)
	}
	if err := verifyNoSymlinkEscape(cleanBase, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// within reports whether child is base itself or lives beneath it, comparing
// already-cleaned paths.
func within(base, child string) bool {
	if child == base {
		return true
	}
	return strings.HasPrefix(child, base+string(os.PathSeparator))
}

// verifyNoSymlinkEscape resolves symlinks on both the base and the target's
// existing prefix and rechecks containment against the real base. The base must
// itself be resolvable; a target whose leaf does not yet exist (a file about to
// be written) is confined by its deepest existing ancestor.
func verifyNoSymlinkEscape(cleanBase, resolved string) error {
	realBase, err := filepath.EvalSymlinks(cleanBase)
	if err != nil {
		return fmt.Errorf("cannot resolve base directory: %w", err)
	}
	realResolved, err := evalExistingPrefix(resolved)
	if err != nil {
		return err
	}
	if !within(realBase, realResolved) {
		return fmt.Errorf("path traversal detected: %q resolves outside base directory via symlink", resolved)
	}
	return nil
}

// evalExistingPrefix resolves symlinks over the longest existing prefix of p,
// then re-appends the non-existent trailing components lexically. This lets a
// path to a not-yet-created file be checked without requiring the leaf to exist.
func evalExistingPrefix(p string) (string, error) {
	cur := p
	var tail []string
	for {
		resolvedCur, err := filepath.EvalSymlinks(cur)
		if err == nil {
			// The existing prefix resolves. If path components remain to be
			// appended, that prefix must be a directory — otherwise the path
			// descends through a regular file. Unix surfaces this as ENOTDIR from
			// EvalSymlinks on the full path; Windows returns an IsNotExist-style
			// error instead, stripping the file component, so check explicitly for
			// consistent behaviour across platforms.
			if len(tail) > 0 {
				info, statErr := os.Stat(resolvedCur)
				if statErr != nil {
					return "", fmt.Errorf("resolving path %q: %w", p, statErr)
				}
				if !info.IsDir() {
					return "", fmt.Errorf("resolving path %q: %q is not a directory", p, cur)
				}
			}
			for i := len(tail) - 1; i >= 0; i-- {
				resolvedCur = filepath.Join(resolvedCur, tail[i])
			}
			return resolvedCur, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolving path %q: %w", p, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("resolving path %q: %w", p, err)
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}
