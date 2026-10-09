/** URI rendering for the SARIF fields the schema puts a format on. */

/** The scheme RFC 3986 requires of an absolute URI. */
const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;

const HEX_DIGITS = '0123456789abcdefABCDEF';
const UPPER_HEX = '0123456789ABCDEF';
const UNESCAPED = "-._~:/?#[]@!$&'()*+,;=";

const encoder = new TextEncoder();

/**
 * Renders s as a valid RFC 3986 URI reference by percent-encoding every byte the
 * grammar does not admit unescaped.
 *
 * SARIF puts format "uri-reference" on artifactLocation.uri, and real scanner
 * output does not respect it: ZAP reports a template placeholder path
 * (".../<%=overview.baseUrl%>") that no URI grammar accepts. Encoding is not a
 * rewrite of the value — it is reversible, and ZAP itself already emits the
 * encoded form of the same construct elsewhere in the same scan. An existing
 * triplet is left alone so a value the source tool already encoded is not
 * double-encoded.
 */
export function encodeUriReference(s: string): string {
  const encoded = percentEncode(s);
  if (URI_SCHEME.test(encoded)) return encoded;
  // RFC 3986 §4.2: a relative reference whose FIRST path segment contains a
  // colon cannot be parsed as one — it reads as a malformed scheme — so that
  // colon is encoded too. Without this the output of a correct percent-encoder
  // is still rejected by the uri-reference format.
  const slash = encoded.indexOf('/');
  const head = slash >= 0 ? encoded.slice(0, slash) : encoded;
  const tail = slash >= 0 ? encoded.slice(slash) : '';
  return head.split(':').join('%3A') + tail;
}

/**
 * Escapes every byte RFC 3986 does not admit unescaped, leaving an existing %HH
 * triplet intact.
 */
function percentEncode(s: string): string {
  const bytes = encoder.encode(s);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i] as number;
    const ch = String.fromCharCode(c);
    if (ch === '%') {
      const a = bytes[i + 1];
      const b = bytes[i + 2];
      if (
        a !== undefined &&
        b !== undefined &&
        HEX_DIGITS.includes(String.fromCharCode(a)) &&
        HEX_DIGITS.includes(String.fromCharCode(b))
      ) {
        out += `%${String.fromCharCode(a)}${String.fromCharCode(b)}`;
        i += 2;
        continue;
      }
      out += '%25';
    } else if (uriUnescaped(c, ch)) {
      out += ch;
    } else {
      out += `%${UPPER_HEX[c >> 4]}${UPPER_HEX[c & 0x0f]}`;
    }
  }
  return out;
}

/**
 * Whether a byte may appear unescaped in a URI reference: RFC 3986's unreserved,
 * gen-delims and sub-delims sets.
 */
function uriUnescaped(c: number, ch: string): boolean {
  if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39)) return true;
  return UNESCAPED.includes(ch);
}

/**
 * Renders s for the SARIF fields whose format is "uri", which requires a scheme.
 * A relative path or a line of free text is not an absolute URI, and emitting one
 * into helpUri would make the document schema-invalid, so it is dropped — the raw
 * value still travels in the HDF property bag.
 */
export function absoluteUri(s: string): string {
  if (!URI_SCHEME.test(s)) return '';
  return encodeUriReference(s);
}
