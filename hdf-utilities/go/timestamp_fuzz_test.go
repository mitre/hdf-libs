package hdfutil

import (
	"strings"
	"testing"
	"time"
)

// FuzzParseTimestamp checks ParseTimestamp's contract on arbitrary input:
// it never panics, and any non-zero result is canonical (UTC, millisecond
// precision) and survives a format/re-parse round trip unchanged.
func FuzzParseTimestamp(f *testing.F) {
	// One seed per documented format, plus adversarial shapes.
	seeds := []string{
		"2026-03-25T22:56:27.736808Z",     // RFC3339Nano
		"2026-03-25T22:56:27Z",            // RFC3339
		"Wed, 25 Mar 2026 22:56:27 -0700", // RFC1123Z
		"Wed, 25 Mar 2026 22:56:27 MST",   // RFC1123
		"2026-03-25T22:56:27",             // bare ISO 8601
		"2026-03-25 22:56:27 -0700",       // InSpec with offset
		"2026-03-25 22:56:27",             // InSpec without offset
		"Wed Mar 25 22:56:27 2026",        // Nessus
		"",                                // empty
		"not a timestamp",                 // garbage
		"0001-01-01T00:00:00Z",            // parses to the zero time
		"9999-12-31T23:59:59.999999999Z",  // max 4-digit year, max fraction
		"2026-03-25T22:56:27+99:99",       // absurd offset
		"2026-03-25T22:56:27.\x00Z",       // NUL byte
		"２０２６-03-25T22:56:27Z",            // full-width digits
		"2026-03-25T22:56:27." + strings.Repeat("9", 100) + "Z", // huge fraction
		strings.Repeat("2026-03-25T22:56:27Z", 50),              // repeated
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := ParseTimestamp(s)
		if got.IsZero() {
			return
		}
		if got.Location() != time.UTC {
			t.Errorf("ParseTimestamp(%q) location = %v, want UTC", s, got.Location())
		}
		if !got.Equal(got.Truncate(time.Millisecond)) {
			t.Errorf("ParseTimestamp(%q) = %v, not millisecond-truncated", s, got)
		}
		// Canonical form must round-trip: rendering and re-parsing cannot
		// change the instant, or the two languages could disagree.
		rendered := got.Format(time.RFC3339Nano)
		reparsed := ParseTimestamp(rendered)
		if !reparsed.Equal(got) {
			t.Errorf("round trip: ParseTimestamp(%q) = %v, but re-parsing its rendering %q = %v", s, got, rendered, reparsed)
		}
	})
}
