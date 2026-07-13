package hdfutil

import (
	"regexp"
	"time"
)

// NormalizeTimestamp converts a parsed time to HDF's canonical form: UTC at
// millisecond precision. Apply it to the result of any custom time.Parse (for
// a vendor-specific layout ParseTimestamp does not cover) so converter output
// is UTC and byte-identical to the TypeScript converters, regardless of the
// source offset or sub-millisecond precision. The zero time is returned
// unchanged.
func NormalizeTimestamp(t time.Time) time.Time {
	return t.UTC().Truncate(time.Millisecond)
}

// ParseTimestamp tries multiple common timestamp formats and returns the first
// successful parse, normalized to HDF's canonical form: UTC at millisecond
// precision. Returns zero time if none match.
//
// Normalizing to UTC (rather than preserving the source offset) gives a single
// deterministic rendering when marshaled as RFC3339Nano, byte-identical to the
// TypeScript converters. Millisecond truncation matches JavaScript's Date
// resolution so the two languages cannot diverge on sub-millisecond fractions.
//
// Supported formats: RFC3339Nano, RFC3339, RFC1123Z, RFC1123, bare ISO 8601,
// InSpec ("2006-01-02 15:04:05 -0700" and "2006-01-02 15:04:05"),
// and the Nessus-specific "Mon Jan 02 15:04:05 2006" format.
func ParseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05",
		"Mon Jan 02 15:04:05 2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return NormalizeTimestamp(t)
		}
	}

	return time.Time{}
}

// bareISOTimestamp matches a JSON string whose entire value is an ISO-8601
// date-time with no zone designator (e.g. "2026-03-25T22:56:27.736808").
var bareISOTimestamp = regexp.MustCompile(`"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)"`)

// NormalizeHDFTimestamps rewrites zone-less timestamps in an HDF document to
// HDF's canonical trimmed-UTC RFC3339 form, in place, before the document is
// decoded.
//
// Real HDF carries them: InSpec emits startTime with no offset, and the schema's
// Go types decode date-time fields into time.Time, whose encoding/json decoder
// demands an offset and hard-fails on a bare value — so every Go consumer
// rejected documents TypeScript happily read. Rewriting them here means both
// languages ingest the same real-world files, and both read a zone-less value as
// UTC (what ParseTimestamp and its TypeScript twin already do) rather than
// silently disagreeing about which wall clock it belonged to.
func NormalizeHDFTimestamps(data []byte) []byte {
	return bareISOTimestamp.ReplaceAllFunc(data, func(match []byte) []byte {
		t := ParseTimestamp(string(match[1 : len(match)-1]))
		if t.IsZero() {
			return match
		}
		return []byte(`"` + t.Format(time.RFC3339Nano) + `"`)
	})
}
