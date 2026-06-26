package hdfutil

import "time"

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
			return t.UTC().Truncate(time.Millisecond)
		}
	}

	return time.Time{}
}
