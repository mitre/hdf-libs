package hdftosarif

import (
	"regexp"
	"strings"
)

// uriScheme matches the scheme RFC 3986 requires of an absolute URI.
var uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// hexDigits is the pct-encoded alphabet, used to tell an existing %HH triplet
// from a bare percent sign.
const hexDigits = "0123456789abcdefABCDEF"

// EncodeURIReference renders s as a valid RFC 3986 URI reference by
// percent-encoding every byte the grammar does not admit unescaped.
//
// SARIF puts format "uri-reference" on artifactLocation.uri, and real scanner
// output does not respect it: ZAP reports a template placeholder path
// (".../<%=overview.baseUrl%>") that no URI grammar accepts. Encoding is not a
// rewrite of the value — it is reversible, and ZAP itself already emits the
// encoded form of the same construct elsewhere in the same scan. An existing
// triplet is left alone so a value the source tool already encoded is not
// double-encoded.
func EncodeURIReference(s string) string {
	encoded := percentEncode(s)
	if uriScheme.MatchString(encoded) {
		return encoded
	}
	// RFC 3986 §4.2: a relative reference whose FIRST path segment contains a
	// colon cannot be parsed as one — it reads as a malformed scheme — so that
	// colon is encoded too. Without this the output of a correct percent-encoder
	// is still rejected by the uri-reference format.
	head, tail := encoded, ""
	if slash := strings.IndexByte(encoded, '/'); slash >= 0 {
		head, tail = encoded[:slash], encoded[slash:]
	}
	return strings.ReplaceAll(head, ":", "%3A") + tail
}

// percentEncode escapes every byte RFC 3986 does not admit unescaped, leaving an
// existing %HH triplet intact.
func percentEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			if i+2 < len(s) &&
				strings.IndexByte(hexDigits, s[i+1]) >= 0 &&
				strings.IndexByte(hexDigits, s[i+2]) >= 0 {
				b.WriteString(s[i : i+3])
				i += 2
				continue
			}
			b.WriteString("%25")
		case uriUnescaped(c):
			b.WriteByte(c)
		default:
			const upperhex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0F])
		}
	}
	return b.String()
}

// uriUnescaped reports whether a byte may appear unescaped in a URI reference:
// RFC 3986's unreserved, gen-delims and sub-delims sets.
func uriUnescaped(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("-._~:/?#[]@!$&'()*+,;=", c) >= 0
}

// AbsoluteURI renders s for the SARIF fields whose format is "uri", which
// requires a scheme. A relative path or a line of free text is not an absolute
// URI, and emitting one into helpUri would make the document schema-invalid, so
// it is dropped — the raw value still travels in the HDF property bag.
func AbsoluteURI(s string) string {
	if !uriScheme.MatchString(s) {
		return ""
	}
	return EncodeURIReference(s)
}
