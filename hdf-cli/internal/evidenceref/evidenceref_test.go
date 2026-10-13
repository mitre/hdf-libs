package evidenceref

import (
	"path/filepath"
	"testing"
)

// The contract this package exists to hold, tested directly rather than only through the
// commands. Added because THREE separate completeness misses on 52n0c.31 — a dedup loop,
// bundle's -o guard, and add-evidence's duplicate index — were all consumers resolving a
// reference the wrong way, and the package they all now depend on had no tests of its
// own. Indirect coverage through CLI integration tests could not say which half was
// wrong when one of them broke.
func TestDecodeThenPath_ConfinesTheDecodedForm(t *testing.T) {
	base := t.TempDir()
	for _, tc := range []struct {
		why, uri  string
		contained bool
	}{
		{"an ordinary reference", "scans/q4.json", true},
		{"the legal spelling of a name with a space", "my%20scans/q4.json", true},
		{"a literal space, which the old byte-path reading accepted", "my scans/q4.json", true},
		{"a literal traversal", "../escape.json", false},
		{"a traversal the DECODE creates — the whole reason order matters", "%2e%2e/escape.json", false},
		{"the same traversal with only the separator encoded", "..%2fescape.json", false},
		{"an encoded separator, which is a nested path and not an escape", "a%2Fb.json", true},
	} {
		t.Run(tc.why, func(t *testing.T) {
			decoded, err := Decode(tc.uri)
			if err != nil {
				t.Fatalf("decode %q: %v", tc.uri, err)
			}
			got, pathErr := Path(base, decoded)
			if tc.contained {
				if pathErr != nil {
					t.Fatalf("%q must resolve inside the package: %v", tc.uri, pathErr)
				}
				if rel, relErr := filepath.Rel(base, got); relErr != nil || rel == ".." {
					t.Errorf("%q resolved to %q, which is not inside %q", tc.uri, got, base)
				}
				return
			}
			if pathErr == nil {
				t.Fatalf("%q decodes to a traversal and must NOT resolve; got %q", tc.uri, got)
			}
		})
	}
}

// Decode and Encode are inverses for the names this field has to carry, which is what
// makes a filename containing a space or a percent expressible at all.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	for _, name := range []string{
		"scans/q4.json", "my scans/q4.json", "100%done.json", "tag#frag.json", "a b/c d.json",
		// A sub-delim RFC 3986 admits unescaped in a segment. The hand-rolled encoder
		// escaped it to %3B, writing a different reference than a conforming producer
		// would for the same filename — and no test noticed, because a round trip
		// survives over-escaping. Pinned on the ENCODED form below, not just the trip.
		"semi;colon.json",
	} {
		encoded := Encode(name)
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("Encode(%q) = %q, which Decode rejects: %v", name, encoded, err)
		}
		if string(decoded) != name {
			t.Errorf("round trip of %q gave %q via %q", name, decoded, encoded)
		}
	}
}

// Encode escapes each SEGMENT and not the separators. Pinned because escaping the whole
// path turned every ordinary "scans/x.json" into "scans%2Fx.json" — a different and wrong
// reference — and that silently stopped evidence set normalizing anything.
func TestEncode_LeavesSeparatorsAlone(t *testing.T) {
	if got := Encode("scans/sub/q4.json"); got != "scans/sub/q4.json" {
		t.Errorf("an ordinary path must be unchanged, got %q", got)
	}
	if got := Encode("my scans/q4.json"); got != "my%20scans/q4.json" {
		t.Errorf("the space escapes and the separator does not, got %q", got)
	}
}

// A malformed escape is reported, never guessed at: falling back to the raw bytes would
// make resolution depend on whether a filename happens to contain a percent.
func TestDecode_ReportsAMalformedEscape(t *testing.T) {
	if _, err := Decode("100%done.json"); err == nil {
		t.Fatal("a bare % introducing no escape must be reported")
	}
	if _, err := Decode(""); err != nil {
		t.Errorf("an empty reference names nothing and is not an error: %v", err)
	}
}

// Encoding matches what net/url produces, character for character. A round trip alone
// cannot catch over-escaping — "semi;colon.json" survives being written "semi%3Bcolon.json"
// and read back — so the spelling itself is asserted. This is the check that was missing
// when a hand-rolled encoder reinvented url.URL.EscapedPath and got one character wrong.
func TestEncode_MatchesTheStandardSpelling(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"scans/q4.json", "scans/q4.json"},
		{"my scans/q4.json", "my%20scans/q4.json"},
		{"100%done.json", "100%25done.json"},
		{"tag#frag.json", "tag%23frag.json"},
		{"q?x.json", "q%3Fx.json"},
		{"semi;colon.json", "semi;colon.json"},
		{"at@sign.json", "at@sign.json"},
		{"eq=sign.json", "eq=sign.json"},
		{"caf\u00e9/r.json", "caf%C3%A9/r.json"},
	} {
		if got := Encode(tc.name); got != tc.want {
			t.Errorf("Encode(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
