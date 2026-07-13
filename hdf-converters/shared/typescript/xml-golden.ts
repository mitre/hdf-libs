/**
 * XML golden comparison cannot be byte-exact the way the NDJSON/CSV exporters
 * are. Go's encoding/xml and the TypeScript builder escape the same characters
 * differently — Go emits numeric character references (&#39;, &#xA;) where TS
 * emits &apos; and literal newlines — and Go's escaping is not configurable.
 * So the two languages canonicalize to a common form before comparing, using
 * THIS function, rather than each test hand-rolling its own (which is how the
 * hdf-to-xml suite ended up asserting the same golden two different ways).
 *
 * Mirrored by NormalizeXMLForGolden in shared/go/xmlgolden.go. The two must stay
 * in lockstep: if you change one, change the other.
 */
export function normalizeXmlForGolden(xml: string): string {
  return xml
    .replace(/<\?xml[^>]*\?>/g, '')
    .replace(/>\s+</g, '><')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#34;|&quot;/g, '"')
    .replace(/&#xA;/gi, '\n')
    .replace(/&#xD;/gi, '\r')
    .replace(/&#x9;/gi, '\t')
    .trim();
}
