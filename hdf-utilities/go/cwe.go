package hdfutil

import (
	"regexp"
	"sort"
)

// CWEPattern matches CWE identifiers like "CWE-79", "CWE 79", "cwe79".
// Pre-compiled at package level to avoid per-call overhead.
var CWEPattern = regexp.MustCompile(`(?i)CWE[- ]?(\d+)`)

// ExtractCWEIDs extracts all numeric CWE IDs from a text string.
// Returns deduplicated sorted list of numeric ID strings (e.g., ["79", "89"]).
func ExtractCWEIDs(text string) []string {
	matches := CWEPattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		id := m[1]
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}
