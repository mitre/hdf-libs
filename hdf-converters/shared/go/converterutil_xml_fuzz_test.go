package shared

import (
	"strings"
	"testing"

	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// FuzzValidateXMLInput checks the XML safety gate on arbitrary input: it
// never panics, is deterministic, agrees with the underlying entity-declaration
// detector, and enforces the size limit exactly.
func FuzzValidateXMLInput(f *testing.F) {
	seeds := []string{
		`<?xml version="1.0"?><root/>`,
		`<!DOCTYPE foo [<!ENTITY a "aaaa">]><foo>&a;</foo>`,                // classic entity decl
		`<!doctype foo [<!entity a "x">]><foo/>`,                           // lowercase
		`<!DOCTYPE foo [ <!ENTITY b SYSTEM "file:///etc/hosts"> ]><foo/>`,  // external
		`<!-- <!ENTITY commented "out"> --><root/>`,                        // decl inside comment
		`<![CDATA[<!ENTITY in-cdata "x">]]>`,                               // decl inside CDATA
		"\xef\xbb\xbf<?xml version=\"1.0\"?><root/>",                       // UTF-8 BOM
		"\xfe\xff\x00<\x00r",                                               // UTF-16-ish bytes
		`<root>` + strings.Repeat("a", 5000) + `<!ENTITY late "x"></root>`, // decl past the 4KB scan window
		``,
		`<`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), 0)
		f.Add([]byte(s), 16)
	}

	f.Fuzz(func(t *testing.T, input []byte, maxSize int) {
		err := ValidateXMLInput(input, maxSize)
		if err2 := ValidateXMLInput(input, maxSize); (err == nil) != (err2 == nil) {
			t.Errorf("non-deterministic verdict for %d-byte input", len(input))
		}
		limit := maxSize
		if limit <= 0 {
			limit = DefaultMaxXMLSize
		}
		if len(input) > limit && err == nil {
			t.Errorf("%d-byte input exceeds limit %d but passed validation", len(input), limit)
		}
		// The gate must be at least as strict as the entity detector: any
		// input the detector flags must be rejected (unless already rejected
		// for size).
		if len(input) <= limit && hdfutil.ContainsXMLEntityDeclarations(input) && err == nil {
			t.Errorf("input contains entity declarations but passed validation")
		}
	})
}
