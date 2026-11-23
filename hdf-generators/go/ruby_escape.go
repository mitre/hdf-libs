package generators

import (
	"fmt"
	"strings"
)

// EscapeQuotes wraps a string as a Ruby string literal whose value is the
// string unchanged:
//   - a control character other than tab or LF → double-quoted (Ruby folds a raw CR)
//   - both single and double quotes → %q() with \, ( and ) escaped
//   - only single quotes → double-quoted with \, " and interpolation escaped
//   - otherwise → single-quoted with \ and ' escaped
//
// Parity: escapeQuotes (TypeScript), pinned by testdata/ruby-literal-cases.json.
func EscapeQuotes(s string) string {
	hasSingle := strings.Contains(s, "'")
	hasDouble := strings.Contains(s, `"`)

	if hasControl(s) || (hasSingle && !hasDouble) {
		return doubleQuoted(s)
	}

	if hasSingle && hasDouble {
		return "%q(" + percentQReplacer.Replace(s) + ")"
	}

	return "'" + singleQuotedReplacer.Replace(s) + "'"
}

var (
	singleQuotedReplacer = strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	percentQReplacer     = strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)
)

func hasControl(s string) bool {
	return strings.ContainsFunc(s, isEscapedControl)
}

func isEscapedControl(r rune) bool {
	return (r < 0x20 && r != '\t' && r != '\n') || r == 0x7f
}

// doubleQuoted escapes \, ", a # that would start #{, #@ or #$ interpolation,
// CR as \r and any other control character as \uXXXX.
func doubleQuoted(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i, r := range s {
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '#' && i+1 < len(s) && strings.IndexByte("{@$", s[i+1]) >= 0:
			b.WriteString(`\#`)
		case r == '\r':
			b.WriteString(`\r`)
		case isEscapedControl(r):
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
