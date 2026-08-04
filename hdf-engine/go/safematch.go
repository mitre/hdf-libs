package hdfengine

import (
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

const (
	// regexTimeout is the maximum time allowed for a regex match operation.
	regexTimeout = 100 * time.Millisecond
	// maxPatternLength is the maximum allowed length for user-provided patterns.
	maxPatternLength = 256
)

// safeRegex wraps regexp2 with timeout protection.
type safeRegex struct {
	re *regexp2.Regexp
}

// compileSafeRegex compiles a regex pattern with timeout protection.
// Returns nil if the pattern is too long or invalid.
func compileSafeRegex(pattern string) *safeRegex {
	if len(pattern) > maxPatternLength {
		return nil
	}

	re, err := regexp2.Compile(pattern, regexp2.IgnoreCase)
	if err != nil {
		return nil
	}

	re.MatchTimeout = regexTimeout
	return &safeRegex{re: re}
}

// matchString returns true if the string matches the pattern.
// Returns false on timeout or error (fail-safe).
func (sr *safeRegex) matchString(s string) bool {
	if sr == nil || sr.re == nil {
		return false
	}

	match, err := sr.re.MatchString(s)
	if err != nil {
		// Timeout or other error - fail safe
		return false
	}

	return match
}

// safeGlobMatch converts a glob pattern to regex and matches with timeout protection.
// Returns false on timeout, invalid pattern, or pattern too long.
func safeGlobMatch(s, pattern string) bool {
	if len(pattern) > maxPatternLength {
		return false
	}

	regexPattern := globToRegex(pattern)
	sr := compileSafeRegex(regexPattern)
	return sr.matchString(s)
}

// globToRegex converts a glob pattern (with * and ? wildcards) to an anchored
// regular expression, escaping all other regex metacharacters.
func globToRegex(glob string) string {
	// Escape regex special chars except * and ?
	special := []string{".", "+", "^", "$", "(", ")", "[", "]", "{", "}", "|", "\\"}
	result := glob
	for _, s := range special {
		result = strings.ReplaceAll(result, s, "\\"+s)
	}
	// Convert glob wildcards to regex
	result = strings.ReplaceAll(result, "*", ".*")
	result = strings.ReplaceAll(result, "?", ".")
	return "^" + result + "$"
}
