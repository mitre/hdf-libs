import { buildXml } from '@mitre/hdf-utilities';
import { validateInputSize, parseHdf } from '../../../shared/typescript/converterutil.js';

/**
 * Generic, lossless, order-preserving HDF Results -> XML serializer.
 *
 * The document is walked as a plain JSON tree and every key is emitted in
 * source-JSON order, so the output can never silently lag a schema addition the
 * way the previous hand-maintained struct mirror did (it dropped ~30 post-v3.2
 * fields). The Go converter walks the same normalized JSON in the same order, so
 * the two languages emit output that is identical after the shared XML golden
 * normalization for every shape this repo's fixtures and parity tests cover.
 *
 * Equality after that normalization is NOT guaranteed in general, and the reason
 * is structural rather than a fixed list of cases: JSON.parse loses duplicate
 * keys and hoists
 * array-index keys before this builder ever runs, V8's number-to-string forms
 * differ from Go's strconv at the extremes, and Go's encoding/xml sanitizes every
 * XML-illegal rune to U+FFFD where this builder emits it verbatim. This builder
 * also caps nesting depth, which the Go peer does not. Anything landing in those
 * seams can differ; known instances are tracked as cards under the
 * exporter-conformance epic. Assume a shape outside the fixture corpus needs
 * checking against the peer rather than that it is covered.
 */

/**
 * Maps a container (plural) key to the element name emitted for each of its
 * array items. The first six entries reproduce the historical struct-tag child
 * names byte-for-byte (note components -> target, kept for backward
 * compatibility); the rest give the post-v3.2 containers a sensible singular.
 * Any array key not listed falls back to <item>, keeping the serializer lossless
 * and generic for fields added later.
 *
 * Mirrored by pluralToSingular in the Go converter — keep the two in lockstep.
 */
const PLURAL_TO_SINGULAR: Record<string, string> = {
  baselines: 'baseline',
  requirements: 'requirement',
  results: 'result',
  refs: 'ref',
  descriptions: 'description',
  components: 'target',
  statusOverrides: 'statusOverride',
  poams: 'poam',
  milestones: 'milestone',
  cvss: 'cvss',
  cwe: 'cwe',
  groups: 'group',
  affectedPackages: 'affectedPackage'
};

function singularFor(key: string): string {
  return PLURAL_TO_SINGULAR[key] ?? 'item';
}

/**
 * Encode a JSON key to a legal XML element name, reporting whether it had to
 * change. HDF leaves object keys unconstrained — tags carry vendor-namespaced
 * keys like "sonarqube/hash", and additionalProperties lets a converter park
 * native fields anywhere — while XML constrains element names to Name, so an
 * unencoded key produced a document no parser could read.
 *
 * The kept set is ASCII — [A-Za-z0-9._-] — not the far wider set XML Name
 * allows, so the two languages agree by construction rather than by way of two
 * Unicode tables that can drift apart. It costs nothing here: no tag key in this
 * package's converter fixtures is non-ASCII. ':' is deliberately not kept —
 * it is a legal Name character but would invent an undeclared namespace prefix.
 *
 * Mirrored by xmlElementName in the Go converter and pinned to a shared table.
 */
export function xmlElementName(key: string): [string, boolean] {
  const out = [...key].map((ch) => (/[A-Za-z0-9.\-_]/.test(ch) ? ch : '_')).join('');
  const [first = ''] = [...out];
  const name = /[A-Za-z_]/.test(first) ? out : `_${out}`;
  return [name, name !== key];
}

/**
 * The attribute holding the original key of a rewritten element. The prefix is
 * what separates an attribute from a child element in the builder; it cannot
 * collide with a child, because any key spelled this way is itself rewritten.
 */
const NAME_ATTR = '@_name';

/**
 * True for a JSON scalar (string, number, bool) or a null/undefined placeholder.
 * Nested objects and arrays are not scalar, which selects the wrapped
 * object-array rendering.
 */
function isScalar(value: unknown): boolean {
  return value === null || value === undefined || typeof value !== 'object';
}

/** One fast-xml-parser preserveOrder node: a single tag key, plus optional attributes. */
type XmlNode = Record<string, unknown>;

function present(value: unknown): boolean {
  return value !== null && value !== undefined;
}

/**
 * Render one JSON key as the sibling nodes it becomes, mirroring the Go
 * writeValue case for case. A list rather than a single node because a scalar
 * array repeats its key unwrapped, and because two keys can encode to one
 * element name — preserveOrder keeps each at its own position, which a plain
 * object keyed by element name could not.
 */
function nodesFor(key: string, value: unknown): XmlNode[] {
  const [name, rewritten] = xmlElementName(key);
  const attrs = rewritten ? { ':@': { [NAME_ATTR]: key } } : {};

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return [{ [name]: [], ...attrs }]; // empty array -> empty wrapper <key></key>
    }
    if (value.every(isScalar)) {
      return value.filter(present).flatMap((item) => nodesFor(key, item));
    }
    const child = singularFor(key);
    return [{ [name]: value.filter(present).flatMap((item) => nodesFor(child, item)), ...attrs }];
  }
  if (typeof value === 'object') {
    return [{ [name]: buildNodes(value as Record<string, unknown>), ...attrs }];
  }
  return [{ [name]: [{ '#text': value }], ...attrs }];
}

/**
 * Walk a JSON object into fast-xml-parser preserveOrder nodes, emitting keys in
 * source order. Null-valued keys are omitted, matching the old omitempty
 * semantics and the Go peer.
 */
function buildNodes(obj: Record<string, unknown>): XmlNode[] {
  return Object.entries(obj).flatMap(([key, value]) => (present(value) ? nodesFor(key, value) : []));
}

/**
 * Convert HDF Results JSON to XML.
 *
 * @param input HDF JSON string
 * @returns XML string
 */
export function convertHdfToXml(input: string): string {
  validateInputSize(input, 'hdf-to-xml');
  // parseHdf normalizes zone-less timestamps to canonical trimmed-UTC RFC3339
  // before parsing, so emitting timestamp strings verbatim yields the canonical
  // form the Go converter also produces.
  const hdf = parseHdf<Record<string, unknown>>(input);

  if (!hdf || typeof hdf !== 'object' || Array.isArray(hdf) || !('baselines' in hdf)) {
    throw new Error('Invalid HDF structure: missing baselines field');
  }
  if (!Array.isArray(hdf.baselines)) {
    throw new Error('Invalid HDF structure: baselines must be an array');
  }

  // preserveOrder frames the document differently — a leading newline and no
  // trailing one — which the golden normalizer's trim() hides. Restored so a
  // caller concatenating an XML prolog still gets a valid document.
  const xml = buildXml([{ HdfResults: buildNodes(hdf) }], {
    preserveOrder: true,
    attributeNamePrefix: '@_',
  });
  return `${xml.trim()}\n`;
}
