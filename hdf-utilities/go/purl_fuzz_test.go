package hdfutil

import (
	"reflect"
	"strings"
	"testing"
)

// FuzzParsePurl checks ParsePurl on arbitrary input: it never panics, is
// deterministic, returns nil only for inputs lacking the pkg: prefix or a
// type, and any parsed result preserves the raw input, carries a non-empty
// lowercased type free of separator characters, and never holds an
// empty-but-present optional segment.
func FuzzParsePurl(f *testing.F) {
	seeds := []string{
		"pkg:npm/%40angular/animation@12.3.1",
		"pkg:golang/github.com/mitre/hdf-libs@v3.0.0",
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0?classifier=sources&repository_url=repo.maven.org#src/main",
		"pkg:rpm/redhat/openssl@1.1.1k-5?arch=x86_64",
		"pkg:gem/rails@%36", // encoded version
		"pkg:npm/foo%zz@1",  // invalid percent-encoding falls back verbatim
		"pkg:",              // no type
		"pkg:///",           // slashes only
		"pkg:npm/",          // no name
		"pkg:npm/name@",     // empty version
		"pkg:npm/@1.2.3",    // empty name with version
		"pkg:npm/x?a&b=&=c", // degenerate qualifiers
		"pkg:npm/x#",        // empty subpath
		"PKG:npm/x",         // prefix is case-sensitive
		"notapurl",
		"",
		"pkg:npm/a\x00b@1",
		"pkg:npm/日本語@1.0",
		"pkg:" + strings.Repeat("a/", 500) + "leaf@1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		p := ParsePurl(s)
		if !reflect.DeepEqual(p, ParsePurl(s)) {
			t.Errorf("ParsePurl(%q) not deterministic", s)
		}
		if p == nil {
			return
		}
		if !strings.HasPrefix(s, "pkg:") {
			t.Errorf("ParsePurl(%q) parsed input without pkg: prefix", s)
		}
		if p.Raw != s {
			t.Errorf("ParsePurl(%q) Raw = %q, want input preserved", s, p.Raw)
		}
		if p.Type == "" || p.Type != strings.ToLower(p.Type) {
			t.Errorf("ParsePurl(%q) Type = %q, want non-empty lowercase", s, p.Type)
		}
		if strings.ContainsAny(p.Type, "/?#") {
			t.Errorf("ParsePurl(%q) Type = %q contains separator characters", s, p.Type)
		}
		if p.Namespace != nil && *p.Namespace == "" {
			t.Errorf("ParsePurl(%q) has present-but-empty Namespace", s)
		}
		if p.Version != nil && *p.Version == "" {
			t.Errorf("ParsePurl(%q) has present-but-empty Version", s)
		}
		if p.Subpath != nil && *p.Subpath == "" {
			t.Errorf("ParsePurl(%q) has present-but-empty Subpath", s)
		}
		if p.Qualifiers == nil {
			t.Errorf("ParsePurl(%q) Qualifiers is nil, want empty map", s)
		}
	})
}
