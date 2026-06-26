package hdfutil

import (
	"testing"
	"time"
)

// ParseTimestamp must return a UTC, millisecond-precision instant for every
// recognized format. HDF's canonical timestamp form is trimmed-UTC RFC3339;
// marshaling the returned time.Time as RFC3339Nano must reproduce it exactly
// (and identically to the TypeScript converters).
func TestParseTimestampNormalizesToUTC(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string // RFC3339Nano marshaling of the parsed time
	}{
		{"zone-less ISO is treated as UTC", "2012-12-10T13:47:29", "2012-12-10T13:47:29Z"},
		{"explicit Z is preserved", "2024-11-15T10:30:00Z", "2024-11-15T10:30:00Z"},
		{"explicit offset is converted to UTC", "2026-02-22T15:57:06-05:00", "2026-02-22T20:57:06Z"},
		{"InSpec space format with offset converts to UTC", "2006-01-02 15:04:05 -0700", "2006-01-02T22:04:05Z"},
		{"InSpec space format zone-less is UTC", "2006-01-02 15:04:05", "2006-01-02T15:04:05Z"},
		{"fractional trailing zeros trimmed", "2024-01-01T00:00:00.120Z", "2024-01-01T00:00:00.12Z"},
		{"sub-millisecond truncated to ms", "2024-01-01T00:00:00.123456789Z", "2024-01-01T00:00:00.123Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseTimestamp(tc.input)
			if got.Location() != time.UTC {
				t.Errorf("location = %v, want UTC", got.Location())
			}
			if marshaled := got.Format(time.RFC3339Nano); marshaled != tc.want {
				t.Errorf("ParseTimestamp(%q) marshaled = %q, want %q", tc.input, marshaled, tc.want)
			}
		})
	}
}

func TestParseTimestampZeroOnUnparseable(t *testing.T) {
	for _, in := range []string{"", "   ", "not a timestamp"} {
		if got := ParseTimestamp(in); !got.IsZero() {
			t.Errorf("ParseTimestamp(%q) = %v, want zero time", in, got)
		}
	}
}
