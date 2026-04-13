package hdfutil

import "time"

// ParseTimestamp tries multiple common timestamp formats and returns the first
// successful parse. Returns zero time if none match.
//
// Supported formats: RFC3339Nano, RFC3339, RFC1123Z, RFC1123, and the
// Nessus-specific "Mon Jan 02 15:04:05 2006" format.
func ParseTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}

	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		"2006-01-02T15:04:05",
		"Mon Jan 02 15:04:05 2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, nil
}
