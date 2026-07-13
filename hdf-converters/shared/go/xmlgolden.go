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
	reInterTagSpace  = regexp.MustCompile(`>\s+<`)
)

var xmlEntityDecoder = strings.NewReplacer(
	"&#39;", "'", "&apos;", "'",
	"&#34;", "\"", "&quot;", "\"",
	"&#xA;", "\n", "&#xa;", "\n",
	"&#xD;", "\r", "&#xd;", "\r",
	"&#x9;", "\t",
)

// NormalizeXMLForGolden canonicalizes XML so a Go and a TypeScript serializer
// compare equal against the same golden: drop the XML declaration, collapse
// inter-tag whitespace, and decode the entity references the two escape
// differently.
func NormalizeXMLForGolden(s string) string {
	s = reXMLDeclaration.ReplaceAllString(s, "")
	s = reInterTagSpace.ReplaceAllString(s, "><")
	s = xmlEntityDecoder.Replace(s)
	return strings.TrimSpace(s)
}
