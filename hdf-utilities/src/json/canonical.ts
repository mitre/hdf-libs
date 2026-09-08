/**
 * Canonical JSON — the encoding HDF uses for content-addressed checksums, such
 * as the amendment chain's `previousChecksum`.
 *
 * The form is Go's `encoding/json` object encoding of the value's JSON shape:
 *
 * - object keys sorted by UTF-8 byte order;
 * - `<`, `>`, `&`, U+2028 and U+2029 escaped;
 * - keys whose value is `null` removed, so a document that spells an absent
 *   optional field as an explicit null hashes the same as one that omits it;
 * - unpaired surrogates replaced with U+FFFD, in keys and string values alike,
 *   because Go's `json.Unmarshal` substitutes them at parse time while JS's
 *   `JSON.parse` preserves them — without this the two disagree on any string
 *   carrying a truncated UTF-16 sequence;
 * - negative zero emitted as `-0`, which `JSON.stringify` renders as `0`;
 * - NaN and Infinity rejected, as Go's encoder rejects them.
 *
 * Every one of those points is a place the two languages would otherwise
 * diverge, and a divergence means a chain written by one is reported as
 * tampered by the other. The Go counterpart is `hdfutil.CanonicalJSON`, and the
 * two are pinned against shared vectors in
 * `hdf-utilities/testdata/canonical-json-vectors.json`.
 */

const LINE_SEPARATOR = '\u2028';
const PARAGRAPH_SEPARATOR = '\u2029';

/** Characters Go's encoder escapes that `JSON.stringify` leaves literal. */
const GO_ESCAPES: Record<string, string> = {
  '<': '\\u003c',
  '>': '\\u003e',
  '&': '\\u0026',
  [LINE_SEPARATOR]: '\\u2028',
  [PARAGRAPH_SEPARATOR]: '\\u2029',
};

const GO_ESCAPE_PATTERN = /[<>&\u2028\u2029]/g;

/** An unpaired high or low surrogate — a truncated UTF-16 sequence. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

const utf8 = new TextEncoder();

/**
 * Compares two keys by their UTF-8 bytes, which is how Go orders map keys.
 * `Array.prototype.sort` compares UTF-16 code units instead, and the two
 * disagree for characters outside the BMP.
 */
function compareUtf8(a: string, b: string): number {
  const left = utf8.encode(a);
  const right = utf8.encode(b);
  const shared = Math.min(left.length, right.length);
  for (let i = 0; i < shared; i++) {
    // Indices below the shared length are always present; the fallbacks keep
    // this total for the type checker without asserting.
    const leftByte = left[i] ?? 0;
    const rightByte = right[i] ?? 0;
    if (leftByte !== rightByte) return leftByte - rightByte;
  }
  return left.length - right.length;
}

/**
 * Replaces unpaired surrogates with U+FFFD, matching what Go's `json.Unmarshal`
 * does when it decodes the same bytes. Applied to keys as well as values, and
 * before sorting, so a key that normalizes onto an existing one collides the
 * same way it would in a Go map (last occurrence wins).
 */
function replaceLoneSurrogates(value: string): string {
  return value.replace(LONE_SURROGATE, '\uFFFD');
}

/**
 * Normalizes a value into the shape that gets hashed. This replaces a
 * `JSON.parse(JSON.stringify(...))` round-trip, which would have been simpler
 * but silently destroys negative zero.
 */
function normalize(value: unknown): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === 'object') {
    const withToJson = value as { toJSON?: () => unknown };
    // Dates and anything else that defines toJSON serialize through it, exactly
    // as JSON.stringify would.
    if (typeof withToJson.toJSON === 'function') return normalize(withToJson.toJSON());

    if (Array.isArray(value)) {
      // JSON has no undefined: in an array position it becomes null.
      return value.map((element) => (element === undefined ? null : normalize(element)));
    }

    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if (nested === null || nested === undefined) continue;
      out[replaceLoneSurrogates(key)] = normalize(nested);
    }
    return out;
  }

  if (typeof value === 'string') return replaceLoneSurrogates(value);

  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new TypeError(`value is not JSON-encodable: ${String(value)}`);
  }

  return value;
}

/** Serializes with object keys in UTF-8 byte order at every level. */
function serialize(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(serialize).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value as Record<string, unknown>)
      .sort(compareUtf8)
      .map((key) => `${serialize(key)}:${serialize((value as Record<string, unknown>)[key])}`);
    return `{${entries.join(',')}}`;
  }
  // Go distinguishes negative zero; JSON.stringify renders it as "0".
  if (typeof value === 'number' && Object.is(value, -0)) return '-0';

  const encoded = JSON.stringify(value);
  if (encoded === undefined) {
    throw new TypeError('value is not JSON-encodable');
  }
  return encoded.replace(GO_ESCAPE_PATTERN, (c) => GO_ESCAPES[c] ?? c);
}

/** Returns the canonical JSON encoding of a value. */
export function canonicalJson(value: unknown): string {
  return serialize(normalize(value ?? null));
}

/** Returns the hex-encoded SHA-256 of a value's canonical JSON encoding. */
export async function canonicalChecksum(value: unknown): Promise<string> {
  const bytes = utf8.encode(canonicalJson(value));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
