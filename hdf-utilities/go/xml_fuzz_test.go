package hdfutil

import (
	"regexp"
	"strings"
	"testing"
)

// xmlNameRe is the element-name grammar ExtractXMLRootElement promises: a
// letter or underscore, then letters, digits, underscore, dot, or hyphen.
var xmlNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

// FuzzExtractXMLRootElement checks ExtractXMLRootElement on arbitrary input:
// it never panics, is deterministic, and any non-empty result is a
// prefix-free element name drawn verbatim from the input.
func FuzzExtractXMLRootElement(f *testing.F) {
	seeds := []string{
		"<root/>",
		`<?xml version="1.0" encoding="UTF-8"?><TestResult xmlns="http://example.com">`,
		"<!-- leading comment --><ns:Element attr='x'>",
		"<!DOCTYPE html><html>",
		"<!DOCTYPE foo [ <!ENTITY x \"y\"> ]><foo>",
		"<!DOCTYPE unterminated",
		"<?pi never ends",
		"<!--",
		"<![CDATA[<fake>]]><real>",
		"  \t\r\n<a.b-c_d>",
		"<1abc>",    // digits cannot start a name
		"<:orphan>", // empty prefix
		"<ns1:ns2:elem>",
		"<",
		"",
		"plain text, no markup",
		"<\x00root>",
		"<élément>",
		"<?a?><!--b--><!DOCTYPE c><?d?><e>",
		strings.Repeat("<!-- spacer -->", 500) + "<deep>",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		name := ExtractXMLRootElement(s)
		if name != ExtractXMLRootElement(s) {
			t.Errorf("ExtractXMLRootElement(%q) not deterministic", s)
		}
		if name == "" {
			return
		}
		if !xmlNameRe.MatchString(name) {
			t.Errorf("ExtractXMLRootElement(%q) = %q, not a valid element name", s, name)
		}
		if !strings.Contains(s, name) {
			t.Errorf("ExtractXMLRootElement(%q) = %q, not a substring of the input", s, name)
		}
	})
}
