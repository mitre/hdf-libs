package hdfutil

import "strings"

// ToKebabCase converts a string to a URL-safe kebab-case slug.
// Lowercases, replaces non-alphanumeric characters with hyphens,
// deduplicates consecutive hyphens, trims leading/trailing hyphens,
// and truncates to 80 characters.
func ToKebabCase(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
