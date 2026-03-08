package generators

import "strings"

// EscapeQuotes wraps a string as a Ruby string literal.
//
// Strategy:
//   - Both single and double quotes → %q() wrapper
//   - Only single quotes → double-quoted with backslash escaping
//   - Otherwise → single-quoted with backslash escaping
func EscapeQuotes(s string) string {
	hasSingle := strings.Contains(s, "'")
	hasDouble := strings.Contains(s, `"`)

	if hasSingle && hasDouble {
		// %q() — escape backslashes before ) so Ruby doesn't treat \) as escaped delimiter
		escaped := strings.ReplaceAll(s, `\)`, `\\)`)
		return "%q(" + escaped + ")"
	}

	if hasSingle {
		// Double-quoted: escape backslashes, then double quotes
		escaped := strings.ReplaceAll(s, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		return `"` + escaped + `"`
	}

	// Single-quoted: escape backslashes, then single quotes
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return "'" + escaped + "'"
}
