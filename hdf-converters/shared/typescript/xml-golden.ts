/**
 * XML golden comparison cannot be byte-exact the way the NDJSON/CSV exporters
 * are. Go's encoding/xml and the TypeScript builder escape the same characters
 * differently — Go emits numeric character references (&#39;, &#xA;) where TS
 * emits &apos; and literal newlines — and Go's escaping is not configurable.
 * So the two languages canonicalize to a common form before comparing, using
 * THIS function, rather than each test hand-rolling its own (which is how the
 * hdf-to-xml suite ended up asserting the same golden two different ways).
 *
 * Whitespace that is an element's whole content is encoded before the collapse
 * and decoded after, so the collapse cannot reach it. Without that step the
 * collapse erased it, which made <k>\t</k> compare equal to <k></k> — masking a
 * real difference — while a peer that emitted the same content as &#x9; survived
 * and compared unequal.
 *
 * Mirrored by NormalizeXMLForGolden in shared/go/xmlgolden.go. The two must stay
 * in lockstep: if you change one, change the other.
 */
const WHITESPACE_ENTITY: Record<string, string> = {
  '\n': '&#xA;',
  '\r': '&#xD;',
  '\t': '&#x9;',
  ' ': '&#x20;',
};

export function normalizeXmlForGolden(xml: string): string {
  return xml
    .replace(/<\?xml[^>]*\?>/g, '')
    // This class must equal the collapse class below: narrower and content the
    // collapse reaches goes unprotected and is erased; wider is merely inert.
    //
    // The class is XML's own S production — space, tab, CR, LF — not \s, which
    // is wider here than in Go's RE2 (vertical tab and the unicode spaces) and
    // wider than S in both (form feed). Its extra members have no encoder entry,
    // so a \s-based collapse erases them rather than protecting them.
    //
    // Only an OPEN tag immediately followed by a close tag delimits content, so
    // the preceding tag is matched in full: it must start with a name character
    // (excluding "</...") and must not end in "/" (excluding "<.../>"). Mirrors
    // the Go peer, which has no lookbehind, so both spell it the same way.
    .replace(/(<[A-Za-z_][\w.:-]*(?:[^>]*[^/>])?>)([ \t\r\n]+)<\//g, (_m, open: string, ws: string) => {
      const encoded = [...ws].map((ch) => WHITESPACE_ENTITY[ch] ?? ch).join('');
      return `${open}${encoded}</`;
    })
    .replace(/>[ \t\r\n]+</g, '><')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#34;|&quot;/g, '"')
    .replace(/&#x[Aa];/g, '\n')
    .replace(/&#x[Dd];/g, '\r')
    .replace(/&#x9;/g, '\t')
    .replace(/&#x20;/g, ' ')
    // Spelled out for the same reason the collapse class is: trim() and Go's
    // TrimSpace are whitespace predicates over different sets — trim() includes
    // U+FEFF and every unicode space, TrimSpace includes U+0085 — so either
    // shorthand makes the two languages disagree about the document boundary.
    // This is XML's S production plus the BOM.
    .replace(/^[ \t\r\n\uFEFF]+|[ \t\r\n\uFEFF]+$/g, '');
}
