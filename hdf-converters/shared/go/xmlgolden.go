package shared

import (
	"regexp"
	"strings"
)

// XML golden comparison cannot be byte-exact the way the NDJSON/CSV exporters
// are. Go's encoding/xml and the TypeScript builder escape the same characters
// differently — Go emits numeric character references (&#39;, &#xA;) where TS
// emits &apos; and literal newlines — and Go's escaping is not configurable.
// So the two languages canonicalize to a common form before comparing, using
// THIS function, rather than each test hand-rolling its own (which is how the
// hdf-to-xml suite ended up asserting the same golden two different ways).
//
// Mirrored by normalizeXmlForGolden in shared/typescript/xml-golden.ts. The two
// must stay in lockstep: if you change one, change the other.
var (
	reXMLDeclaration = regexp.MustCompile(`<\?xml[^>]*\?>`)
	reInterTagSpace  = regexp.MustCompile(`>[ \t\r\n]+<`)
	// This class must equal the collapse class above: narrower and content the
	// collapse reaches goes unprotected and is erased; wider is merely inert.
	//
	// The class is XML's own S production — space, tab, CR, LF — not a regex \s
	// shorthand. Both languages' \s adds form feed; JavaScript's adds vertical tab
	// and the unicode spaces on top, so the two would collapse different sets. Any
	// character collapsed here but absent from the encoder below is erased rather
	// than protected, which is how form feed was lost in both languages at once.
	//
	// Whitespace that is an element's entire content, not indentation between
	// siblings. Only an OPEN tag immediately followed by a close tag delimits
	// content, so the preceding tag is matched in full: it must start with a name
	// character (excluding "</...") and must not end in "/" (excluding "<.../>").
	// RE2 has no lookbehind, hence matching the tag rather than one character.
	reWhitespaceOnlyContent = regexp.MustCompile(`(<[A-Za-z_][\w.:-]*(?:[^>]*[^/>])?>)([ \t\r\n]+)</`)
)

var xmlEntityDecoder = strings.NewReplacer(
	"&#39;", "'", "&apos;", "'",
	"&#34;", "\"", "&quot;", "\"",
	"&#xA;", "\n", "&#xa;", "\n",
	"&#xD;", "\r", "&#xd;", "\r",
	"&#x9;", "\t",
	"&#x20;", " ",
)

// XML's S production plus U+FEFF, which is an encoding artifact rather than
// content wherever it appears at a document boundary.
const xmlBoundaryWhitespace = " \t\r\n\uFEFF"

var xmlWhitespaceEncoder = strings.NewReplacer(
	"\n", "&#xA;",
	"\r", "&#xD;",
	"\t", "&#x9;",
	" ", "&#x20;",
)

// NormalizeXMLForGolden canonicalizes XML so a Go and a TypeScript serializer
// compare equal against the same golden: drop the XML declaration, collapse
// inter-tag whitespace, and decode the entity references the two escape
// differently.
//
// Whitespace that is an element's whole content is encoded before the collapse
// and decoded after, so the collapse cannot reach it. Without that step the
// collapse erased it, which made <k>\t</k> compare equal to <k></k> — masking a
// real difference — while a peer that emitted the same content as &#x9; survived
// and compared unequal.
func NormalizeXMLForGolden(s string) string {
	s = reXMLDeclaration.ReplaceAllString(s, "")
	s = reWhitespaceOnlyContent.ReplaceAllStringFunc(s, func(m string) string {
		sub := reWhitespaceOnlyContent.FindStringSubmatch(m)
		return sub[1] + xmlWhitespaceEncoder.Replace(sub[2]) + "</"
	})
	s = reInterTagSpace.ReplaceAllString(s, "><")
	s = xmlEntityDecoder.Replace(s)
	// Spelled out for the same reason the collapse class is: TrimSpace and
	// JavaScript's trim() are whitespace predicates over different sets — Go's
	// includes U+0085, JavaScript's includes U+FEFF and every unicode space — so
	// either shorthand makes the two languages disagree about the document
	// boundary. This is XML's S production plus the BOM.
	return strings.Trim(s, xmlBoundaryWhitespace)
}
