package cmd

import (
	"regexp"
	"strings"
)

// ANSI escape sequence pattern (covers CSI, OSC, and other sequences).
var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[PX^_][^\x1b]*\x1b\\|\x1b.`)

// sanitizeOutput removes ANSI escape sequences and other potentially dangerous
// control characters from output strings. This prevents terminal injection attacks
// where malicious data in HDF files could manipulate the user's terminal.
func sanitizeOutput(s string) string {
	// Remove ANSI escape sequences
	s = ansiEscapePattern.ReplaceAllString(s, "")

	// Remove other control characters except newline, tab, carriage return
	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		// Allow printable characters, newline, tab, carriage return
		if r >= 32 || r == '\n' || r == '\t' || r == '\r' {
			result.WriteRune(r)
		} else {
			// Replace other control characters with a placeholder
			result.WriteRune('\uFFFD') // Unicode replacement character
		}
	}

	return result.String()
}
