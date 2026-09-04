package hdfutil

import (
	"reflect"
	"strings"
	"testing"
)

// FuzzParseCpe checks ParseCpe on arbitrary input: it never panics, is
// deterministic, parses exactly the inputs carrying the cpe:2.3: prefix, and
// only reports a warning-free result for a valid part value.
func FuzzParseCpe(f *testing.F) {
	seeds := []string{
		"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",   // canonical
		"cpe:2.3:o:canonical:ubuntu_linux:22.04",           // truncated
		"cpe:2.3:h:cisco:asa:9.8:*:*:*:*:*:*:*:extra:more", // extra fields
		"cpe:2.3:z:vendor:product:1.0:*:*:*:*:*:*:*",       // unknown part
		`cpe:2.3:a:vendor\:inc:name\\v:1.0:*:*:*:*:*:*:*`,  // escaped colon and backslash
		`cpe:2.3:a:trailing\`,                              // dangling escape
		"cpe:2.3:",                                         // bare prefix
		"cpe:2.3:::::::::::",                               // all-empty fields
		"cpe:/a:legacy:2.2-style",                          // CPE 2.2 URI, no 2.3 prefix
		"CPE:2.3:a:upper:case:1.0",                         // prefix is case-sensitive
		"not a cpe",
		"",
		"cpe:2.3:a:nul\x00vendor:product:1.0",
		"cpe:2.3:a:日本語:製品:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:" + strings.Repeat(":", 500),
		"cpe:2.3:a:" + strings.Repeat(`\:`, 200),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		p := ParseCpe(s)
		if !reflect.DeepEqual(p, ParseCpe(s)) {
			t.Errorf("ParseCpe(%q) not deterministic", s)
		}
		if (p != nil) != strings.HasPrefix(s, "cpe:2.3:") {
			t.Errorf("ParseCpe(%q) = %v, want a result exactly when the cpe:2.3: prefix is present", s, p)
		}
		if p == nil {
			return
		}
		if p.Raw != s {
			t.Errorf("ParseCpe(%q) Raw = %q, want input preserved", s, p.Raw)
		}
		if len(p.Warnings) == 0 {
			if _, ok := map[string]struct{}{"a": {}, "o": {}, "h": {}, "*": {}}[p.Part]; !ok {
				t.Errorf("ParseCpe(%q) warning-free but Part = %q is not a valid part", s, p.Part)
			}
		}
	})
}
