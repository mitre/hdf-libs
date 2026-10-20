package hdfutil

import (
	"bytes"
	"regexp"
	"strings"
)

// scanXMLPrologue walks the prologue — everything before the root element, the only
// region where a DOCTYPE may legally appear — and reports which declarations it holds.
//
// It reports rather than returning the text to search, because the text would still
// contain commented-out declarations: `<!-- <!DOCTYPE x> -->` is not a declaration, and
// grepping a region that includes it cannot tell the difference.
//
// A fixed byte window cannot bound this region: the prologue may carry any amount of
// comment and processing-instruction text, so a declaration can be pushed past any
// constant. Walking to the root element has no such hole, and it is also what stops
// declaration-shaped CONTENT from false-positiving — once the root is reached, nothing
// after it is a declaration.
//
// An unterminated construct yields no root element, and so no prologue: there is
// nothing a document that never opens an element can be said to have declared.
// XMLPrologueDeclarations is what a document's prologue declares. The three facts are
// separate because they are three different attack surfaces, and which of them a given
// boundary refuses is a policy decision belonging to that boundary, not here:
//
//   - HasExternalID — an external DTD reference (SYSTEM/PUBLIC). The XXE and SSRF vector;
//     dangerous with no inline entity of its own.
//   - HasEntityDecl — an inline <!ENTITY>. The entity-expansion (billion-laughs) vector.
//   - HasDoctype — a DOCTYPE of any kind. A subset of only ELEMENT/ATTLIST/NOTATION is
//     inert: it declares structure and can neither expand nor fetch. Real Burp Suite
//     exports are exactly that shape, so refusing every DOCTYPE refuses a published
//     tool's own output.
type XMLPrologueDeclarations struct {
	HasDoctype    bool
	HasEntityDecl bool
	HasExternalID bool
	// Malformed is set when the prologue could not be parsed to a root element, so the
	// other fields are a lower bound rather than a complete answer. A boundary that
	// treats absence of findings as "safe" must refuse this instead.
	Malformed bool
}

// InspectXMLPrologue reports what the input's prologue declares. A document with no root
// element has no prologue to trust, and reports nothing.
func InspectXMLPrologue(input []byte) XMLPrologueDeclarations {
	decls, foundRoot := scanXMLPrologue(input)
	if !foundRoot {
		// Could not reach a root element. Whatever was seen on the way is reported
		// anyway and Malformed is set: a gate must be able to tell "nothing declared"
		// apart from "could not tell", and refuse the second.
		decls.Malformed = true
	}
	return decls
}

// isDTDNameByte reports whether b can appear in a DTD declaration keyword.
func isDTDNameByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// scanInternalSubset walks a DTD internal subset from the byte after '[' and reports
// what it declares plus the offset just past its closing "]>".
//
// It is a state machine rather than a substring search because the subset's own EXTENT
// depends on quoting: `<!ATTLIST l v CDATA "]>">` contains a `]>` inside a literal, and a
// scanner that searches for the first `]>` ends the subset there, loses its place, and
// reports a document with a later <!ENTITY> as clean. Comments hide the same way.
// Measured: that evasion defeated the substring version of this function.
func scanInternalSubset(s []byte) (end int, hasEntity, hasExternalID, ok bool) {
	i := 0
	for i < len(s) {
		switch {
		case s[i] == '\'' || s[i] == '"':
			quote := s[i]
			i++
			for i < len(s) && s[i] != quote {
				i++
			}
			if i >= len(s) {
				return 0, hasEntity, hasExternalID, false // unterminated literal
			}
			i++
		case bytes.HasPrefix(s[i:], []byte("<!--")):
			closeAt := bytes.Index(s[i:], []byte("-->"))
			if closeAt == -1 {
				return 0, hasEntity, hasExternalID, false
			}
			i += closeAt + 3
		case bytes.HasPrefix(s[i:], []byte("<!")):
			j := i + 2
			for j < len(s) && isDTDNameByte(s[j]) {
				j++
			}
			if bytes.EqualFold(s[i+2:j], []byte("ENTITY")) {
				hasEntity = true
			}
			i = j
		case s[i] == ']':
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			if j < len(s) && s[j] == '>' {
				return j + 1, hasEntity, hasExternalID, true
			}
			i++
		default:
			// SYSTEM/PUBLIC only counts outside literals and comments, where it is a
			// keyword rather than text. Conservative by design: any external reference in
			// the subset counts, whichever declaration carries it.
			if rest := s[i:]; bytes.HasPrefix(rest, []byte("SYSTEM")) || bytes.HasPrefix(rest, []byte("PUBLIC")) {
				hasExternalID = true
				i += 6
				continue
			}
			i++
		}
	}
	return 0, hasEntity, hasExternalID, false // subset never closed
}

// scanXMLPrologue walks the prologue — everything before the root element — and reports
// what it declares, plus whether a root element was reached at all.
func scanXMLPrologue(input []byte) (decls XMLPrologueDeclarations, foundRoot bool) {
	i := 0
	for {
		for i < len(input) && (input[i] == ' ' || input[i] == '\t' || input[i] == '\n' || input[i] == '\r') {
			i++
		}
		if i >= len(input) {
			return decls, false
		}
		rest := input[i:]
		switch {
		case bytes.HasPrefix(rest, []byte("<?")):
			closeAt := bytes.Index(rest, []byte("?>"))
			if closeAt == -1 {
				return decls, false
			}
			i += closeAt + 2
		case bytes.HasPrefix(rest, []byte("<!--")):
			closeAt := bytes.Index(rest, []byte("-->"))
			if closeAt == -1 {
				return decls, false
			}
			i += closeAt + 3 // skipped as a unit: its contents declare nothing
		case len(rest) >= 9 && bytes.EqualFold(rest[:9], []byte("<!DOCTYPE")):
			// Recorded the moment the token is seen, so this fact is sound no matter what
			// the rest of the declaration does. Everything below only ADDS detail.
			decls.HasDoctype = true
			open := bytes.IndexByte(rest, '[')
			gt := bytes.IndexByte(rest, '>')
			if gt == -1 && open == -1 {
				return decls, false
			}
			if open != -1 && (gt == -1 || open < gt) {
				head := bytes.ToUpper(rest[:open])
				if bytes.Contains(head, []byte("SYSTEM")) || bytes.Contains(head, []byte("PUBLIC")) {
					decls.HasExternalID = true
				}
				consumed, hasEntity, hasExternal, ok := scanInternalSubset(rest[open+1:])
				decls.HasEntityDecl = decls.HasEntityDecl || hasEntity
				decls.HasExternalID = decls.HasExternalID || hasExternal
				if !ok {
					return decls, false
				}
				i += open + 1 + consumed
			} else {
				head := bytes.ToUpper(rest[:gt])
				if bytes.Contains(head, []byte("SYSTEM")) || bytes.Contains(head, []byte("PUBLIC")) {
					decls.HasExternalID = true
				}
				i += gt + 1
			}
		case bytes.HasPrefix(rest, []byte("<!")):
			closeAt := bytes.IndexByte(rest, '>')
			if closeAt == -1 {
				return decls, false
			}
			i += closeAt + 1
		case rest[0] == '<':
			return decls, true // the root element
		default:
			// Character data before any element: not well-formed, nothing to trust.
			return decls, false
		}
	}
}

// ContainsXMLDoctype reports whether the input declares a DOCTYPE before its root
// element.
//
// This is the one fact here that is SOUND rather than best-effort: it is set the moment
// the <!DOCTYPE token is seen, so no amount of quoting or commenting inside the
// declaration can hide it. The entity and external-id facts require reading the
// declaration's contents, which is inherently harder to get right — see
// scanInternalSubset. A boundary that wants a guarantee should gate on this.
func ContainsXMLDoctype(input []byte) bool {
	return InspectXMLPrologue(input).HasDoctype
}

// ContainsXMLEntityDeclarations reports whether the input declares an entity before its
// root element — the billion-laughs shape.
//
// Scans the whole prologue; it previously inspected only the first 4 KB, which a
// declaration could simply be pushed past.
func ContainsXMLEntityDeclarations(input []byte) bool {
	return InspectXMLPrologue(input).HasEntityDecl
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
