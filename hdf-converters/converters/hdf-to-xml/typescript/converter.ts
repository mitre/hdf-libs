import { buildXml } from '@mitre/hdf-utilities';
import { validateInputSize, parseHdf } from '../../../shared/typescript/converterutil.js';

/**
 * Generic, lossless, order-preserving HDF Results -> XML serializer.
 *
 * The document is walked as a plain JSON tree and every key is emitted in
 * source-JSON order, so the output can never silently lag a schema addition the
 * way the previous hand-maintained struct mirror did (it dropped ~30 post-v3.2
 * fields). JSON.parse preserves object key insertion order, and the Go converter
 * walks the same normalized JSON in the same order, so the two languages emit
 * output that is identical after the shared XML golden normalization.
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
 * Wrap a primitive so fast-xml-parser renders it as element text rather than an
 * attribute.
 */
function wrapScalar(value: string | number | boolean): { '#text': string | number | boolean } {
  return { '#text': value };
}

/**
 * True for a JSON scalar (string, number, bool) or a null/undefined placeholder.
 * Nested objects and arrays are not scalar, which selects the wrapped
 * object-array rendering.
 */
function isScalar(value: unknown): boolean {
  return value === null || value === undefined || typeof value !== 'object';
}

/**
 * Convert an object-array item into its fast-xml-parser representation. Items
 * are objects (the object-array rule), but a scalar in a heterogeneous array is
 * wrapped so it renders as <singular>text</singular>, matching the Go walker.
 */
function toXmlValue(value: unknown): unknown {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (Array.isArray(value)) {
    return { item: value.filter(v => v !== null && v !== undefined).map(toXmlValue) };
  }
  if (typeof value === 'object') {
    return buildObject(value as Record<string, unknown>);
  }
  return wrapScalar(value as string | number | boolean);
}

/**
 * Walk a JSON object into a fast-xml-parser-ready structure, emitting keys in
 * source order. Null-valued keys are omitted (parity with the old omitempty
 * semantics). A scalar array repeats its key unwrapped (<nist>AU-12</nist>); an
 * object array becomes a wrapper whose per-item child name comes from the
 * plural->singular map; an empty array becomes an empty wrapper element.
 */
function buildObject(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      const items = value.filter(v => v !== null && v !== undefined);
      if (value.length === 0) {
        out[key] = {}; // empty array -> empty wrapper <key></key>
      } else if (value.every(isScalar)) {
        // Scalar array -> repeated, unwrapped key element.
        out[key] = items.map(v => wrapScalar(v as string | number | boolean));
      } else {
        // Object array -> wrapper element with one singular-named child per item.
        out[key] = { [singularFor(key)]: items.map(toXmlValue) };
      }
    } else if (typeof value === 'object') {
      out[key] = buildObject(value as Record<string, unknown>);
    } else {
      out[key] = wrapScalar(value as string | number | boolean);
    }
  }
  return out;
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

  return buildXml({ HdfResults: buildObject(hdf) });
}
