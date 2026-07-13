package hdfutil

import (
	"regexp"
	"strings"
)

// Pre-compiled regexes for StripHTML — avoids per-call compilation overhead.
// whitespaceRe spells out the character class JavaScript's `\s` matches (Go's
// `\s` is ASCII-only): HTML sources carry NBSP and friends, and the TS twin of
// this helper must normalize them identically.
var (
	htmlTagRe    = regexp.MustCompile(`<[^>]*>`)
	whitespaceRe = regexp.MustCompile(`[\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]+`)
)

// StripHTML removes HTML tags from a string and normalizes whitespace.
// Returns the trimmed plain-text result.
func StripHTML(html string) string {
	stripped := htmlTagRe.ReplaceAllString(html, " ")
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(stripped, " "))
}

// SafeString extracts a string from an any value.
// Returns the zero string if v is nil or not a string.
func SafeString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// SafeStringSlice extracts a string slice from an any value.
// Returns nil if v is nil or not a []any containing strings.
// Non-string elements within the slice are skipped.
func SafeStringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// StringsToInterfaces converts a string slice to an interface slice.
// This is needed because Go's type system does not allow direct assignment
// of []string to []any in JSON-serializable map values.
func StringsToInterfaces(ss []string) []any {
	result := make([]any, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}
