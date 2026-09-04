package hdfutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzSafePath checks SafePath's containment contract on arbitrary
// (base, rel) pairs: it never panics, rejects empty input, and any non-error
// result is a cleaned path lexically inside the cleaned base; against a real
// base directory containing an outward-pointing symlink, any result that
// physically resolves must also land inside the physical base.
func FuzzSafePath(f *testing.F) {
	seeds := [][2]string{
		{"/tmp", "file.txt"},
		{"/tmp", "sub/dir/file.txt"},
		{"/tmp", "../etc/passwd"},
		{"/tmp", ".."},
		{"/tmp", "../../../../../../etc/passwd"},
		{"/tmp", "/etc/passwd"},
		{"/tmp", "a/../../b"},
		{"/tmp", "..\\..\\windows\\system32"},
		{"/tmp", "%2e%2e%2fetc%2fpasswd"},
		{"/tmp", "....//....//etc/passwd"},
		{"/tmp", "."},
		{"/tmp", ""},
		{"/tmp", "a\x00b"},
		{"/tmp", "‥/‥/etc"},
		{"/tmp/", "./a/./b/../c"},
		{"", "x"},
		{".", "x"},
		{"/", "etc/passwd"},
		{"relative/base", "../../outside"},
		{"/tmp/../tmp", strings.Repeat("../", 100) + "etc/passwd"},
		{"/tmp", "escape"},
		{"/tmp", "escape/inner.txt"},
		{"/tmp", strings.Repeat("a/", 200) + "leaf"},
		{"..", ".."},
		{"..", "../secret"},
		{"../pkg", "x"},
		{"../..", "safe.txt"},
		{"..", "inside/../../../etc"},
		{"/tmp", `C:\evil`},
		{"/tmp", `\\server\share\x`},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, base, rel string) {
		assertLexicalContainment(t, base, rel)

		// Real base with a symlink pointing outside it: SafePath must reject
		// any rel that physically escapes through the link.
		root := t.TempDir()
		realBase := filepath.Join(root, "base")
		outside := filepath.Join(root, "outside")
		if err := os.Mkdir(realBase, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(outside, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(realBase, "escape")); err != nil {
			t.Fatal(err)
		}
		assertLexicalContainment(t, realBase, rel)

		got, err := SafePath(realBase, rel)
		if err != nil {
			return
		}
		// Independent oracle via stdlib: if the accepted path exists, its
		// physical location must be inside the physical base.
		realGot, evalErr := filepath.EvalSymlinks(got)
		if evalErr != nil {
			return
		}
		realRoot, evalErr := filepath.EvalSymlinks(realBase)
		if evalErr != nil {
			t.Fatal(evalErr)
		}
		if escapes(realRoot, realGot) {
			t.Errorf("SafePath(%q, %q) = %q, which physically resolves to %q outside the base", realBase, rel, got, realGot)
		}
	})
}

// assertLexicalContainment verifies that a successful SafePath result is a
// cleaned path that does not lexically escape the cleaned base.
func assertLexicalContainment(t *testing.T, base, rel string) {
	t.Helper()
	got, err := SafePath(base, rel)
	if err != nil {
		return
	}
	if rel == "" {
		t.Errorf("SafePath(%q, \"\") = %q, want error for empty path", base, got)
	}
	if got != filepath.Clean(got) {
		t.Errorf("SafePath(%q, %q) = %q, not a cleaned path", base, rel, got)
	}
	if escapes(filepath.Clean(base), got) {
		t.Errorf("SafePath(%q, %q) = %q, escapes the base directory", base, rel, got)
	}
}

// escapes reports whether child lies outside base, judged by filepath.Rel.
func escapes(base, child string) bool {
	rel, err := filepath.Rel(base, child)
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
