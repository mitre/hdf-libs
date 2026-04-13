package hdfutil

import (
	"bytes"
	"regexp"
	"strings"
)

// ContainsXMLEntityDeclarations checks if XML input contains DOCTYPE entity
// declarations which could be used for entity expansion DoS attacks (billion
// laughs). Returns true if entities are found. Only inspects the first 4 KB
// of the input since DOCTYPE declarations must appear before the root element.
func ContainsXMLEntityDeclarations(input []byte) bool {
	limit := min(len(input), 4096)
	upper := bytes.ToUpper(input[:limit])
	return bytes.Contains(upper, []byte("<!ENTITY"))
}

// xmlRootElementRe matches an opening XML element tag, optionally namespace-prefixed.
// Captures the local name (group 1).
var xmlRootElementRe = regexp.MustCompile(`^<(?:[a-zA-Z_][\w.\-]*:)?([a-zA-Z_][\w.\-]*)`)

// ExtractXMLRootElement extracts the root element local name from an XML string.
// It skips XML processing instructions (<?...?>), comments (<!--...-->),
// and DOCTYPE declarations (<!DOCTYPE ... [...]>), and strips namespace prefixes.
// Returns "" if no element is found.
func ExtractXMLRootElement(input string) string {
	s := input
	for {
		s = strings.TrimLeft(s, " \t\n\r")
		if len(s) == 0 {
			return ""
		}
		switch {
		case strings.HasPrefix(s, "<?"):
			end := strings.Index(s, "?>")
			if end == -1 {
				return ""
			}
			s = s[end+2:]
		case strings.HasPrefix(s, "<!--"):
			end := strings.Index(s, "-->")
			if end == -1 {
				return ""
			}
			s = s[end+3:]
		case len(s) >= 9 && strings.EqualFold(s[:9], "<!DOCTYPE"):
			bracket := strings.Index(s, "[")
			gt := strings.Index(s, ">")
			if gt == -1 {
				return ""
			}
			if bracket != -1 && bracket < gt {
				endSubset := strings.Index(s, "]>")
				if endSubset == -1 {
					return ""
				}
				s = s[endSubset+2:]
			} else {
				s = s[gt+1:]
			}
		case strings.HasPrefix(s, "<!"):
			end := strings.Index(s, ">")
			if end == -1 {
				return ""
			}
			s = s[end+1:]
		default:
			m := xmlRootElementRe.FindStringSubmatch(s)
			if m == nil {
				return ""
			}
			return m[1]
		}
	}
}
