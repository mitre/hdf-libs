/**
 * Normalize InSpec exec-json v1 format to HDF v2 structure for diffing.
 *
 * V1 uses: profiles[].controls[].results[].code_desc, source_location, start_time
 * V2 uses: baselines[].requirements[].results[].codeDesc, sourceLocation, startTime
 *
 * This module detects v1 documents and converts them in-memory to v2 shape
 * so the diff engine only needs to handle one format.
 */

import { parseTimestamp } from '@mitre/hdf-utilities';

interface V1Result {
  status: string;
  code_desc?: string;
  codeDesc?: string;
  run_time?: number;
  runTime?: number;
  start_time?: string;
  startTime?: string;
  message?: string;
  [key: string]: unknown;
}

interface V1Control {
  id: string;
  title?: string;
  desc?: string;
  impact: number;
  tags?: Record<string, unknown>;
  refs?: unknown[];
  code?: string;
  descriptions?: unknown[];
  source_location?: { ref?: string; line?: number };
  sourceLocation?: { ref?: string; line?: number };
  results?: V1Result[];
  [key: string]: unknown;
}

interface V1Profile {
  name: string;
  title?: string;
  version?: string;
  sha256?: string;
  controls?: V1Control[];
  groups?: unknown[];
  supports?: unknown[];
  attributes?: unknown[];
  [key: string]: unknown;
}

/**
 * Detect whether a document is v1 (InSpec exec-json) format.
 * V1 has `profiles` at the top level; v2 has `baselines`.
 */
export function isV1Format(doc: Record<string, unknown>): boolean {
  return Array.isArray(doc['profiles']) && !Array.isArray(doc['baselines']);
}

/**
 * Normalize a document to v2-like structure. If already v2, returns as-is.
 * If v1, converts profiles→baselines, controls→requirements, and snake_case→camelCase.
 */
export function normalizeToV2(doc: Record<string, unknown>): Record<string, unknown> {
  if (!isV1Format(doc)) {
    return doc;
  }

  const profiles = doc['profiles'] as V1Profile[];
  const baselines = profiles.map(normalizeProfile);

  return {
    baselines,
    statistics: normalizeStatistics(doc['statistics']),
    timestamp: doc['timestamp'],
  };
}

function normalizeProfile(profile: V1Profile): Record<string, unknown> {
  const controls = profile.controls ?? [];
  const requirements = controls.map(normalizeControl);

  const baseline: Record<string, unknown> = {
    name: profile.name,
    title: profile.title,
    version: profile.version,
    integrity: profile.sha256 ? { algorithm: 'sha256', checksum: profile.sha256 } : undefined,
    groups: normalizeGroups(profile.groups),
    supports: normalizeSupports(profile.supports),
    requirements,
  };

  // Legacy attributes are unstructured maps that do not conform to the typed
  // Input shape, and the differ never reads inputs. Parking them preserves the
  // data without this normalizer taking on the converter's typing job.
  const attributes = profile.attributes ?? [];
  if (attributes.length > 0) {
    baseline.extensions = { passthrough: { legacyAttributes: attributes } };
  }

  return baseline;
}

/** Only a plain object can be projected; a legacy array or scalar carries nothing. */
function plainObject(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

/** Legacy groups name their members `controls`; the declared field is `requirements`. */
function normalizeGroups(groups: unknown[] | undefined): Record<string, unknown>[] {
  return (groups ?? []).flatMap((raw) => {
    const g = plainObject(raw);
    if (!g) return [];
    const group: Record<string, unknown> = {
      id: typeof g.id === 'string' ? g.id : '',
      requirements: Array.isArray(g.controls) ? g.controls.filter((c) => typeof c === 'string') : [],
    };
    if (typeof g.title === 'string') group.title = g.title;
    return [group];
  });
}

/** InSpec writes hyphenated support keys; the declared shape is camelCase. */
function normalizeSupports(supports: unknown[] | undefined): Record<string, string>[] {
  const KEYS: Array<[string, string]> = [
    ['platform', 'platform'],
    ['platform-family', 'platformFamily'],
    ['platform-name', 'platformName'],
    ['release', 'release'],
  ];
  return (supports ?? []).flatMap((raw) => {
    const s = plainObject(raw);
    if (!s) return [];
    const out: Record<string, string> = {};
    for (const [legacyKey, declaredKey] of KEYS) {
      const value = s[legacyKey];
      if (typeof value === 'string' && value !== '') out[declaredKey] = value;
    }
    return Object.keys(out).length > 0 ? [out] : [];
  });
}

/** Duration is the only statistic this normalizer maps; the declared type is closed. */
function normalizeStatistics(stats: unknown): { duration?: number } {
  const duration = (stats as { duration?: unknown } | undefined)?.duration;
  return typeof duration === 'number' ? { duration } : {};
}

/**
 * A Reference with nothing in it fails the schema, which requires one of ref,
 * url or uri. Real InSpec emits `{"ref": []}`, so passing legacy refs through
 * verbatim put empty references into a closed shape. Mirrors the Go twin and
 * convertRef in the legacyhdf-to-hdf converter.
 */
function normalizeRefs(refs: unknown[] | undefined): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const raw of refs ?? []) {
    if (typeof raw === 'string') {
      if (raw !== '') out.push({ ref: raw });
      continue;
    }
    const r = plainObject(raw);
    if (!r) continue;
    const ref: Record<string, unknown> = {};
    const value = normalizeRefValue(r.ref);
    if (value !== undefined) ref.ref = value;
    if (typeof r.url === 'string' && r.url !== '') ref.url = r.url;
    if (typeof r.uri === 'string' && r.uri !== '') ref.uri = r.uri;
    if (Object.keys(ref).length > 0) out.push(ref);
  }
  return out;
}

/** Ref is a string or an array of objects; an empty array carries nothing. */
function normalizeRefValue(raw: unknown): unknown {
  if (typeof raw === 'string') return raw === '' ? undefined : raw;
  if (!Array.isArray(raw)) return undefined;
  const maps = raw.map(plainObject).filter((m) => m !== undefined);
  return maps.length > 0 ? maps : undefined;
}

/** Project rather than copy: the declared SourceLocation is a closed {ref, line}. */
function normalizeSourceLocation(control: V1Control): { ref?: string; line?: number } | undefined {
  // Each key is tried for a usable object rather than taken whichever is merely
  // present: a scalar under source_location shadowed a good sourceLocation, and
  // an array under it yielded {} where Go omitted the key.
  const src = plainObject(control.source_location) ?? plainObject(control.sourceLocation);
  if (!src) return undefined;
  const out: { ref?: string; line?: number } = {};
  if (typeof src.ref === 'string') out.ref = src.ref;
  if (typeof src.line === 'number') out.line = src.line;
  return out;
}

/**
 * A default-labelled description is schema-required (minItems 1 plus a contains
 * constraint), and `descriptions` is one of the fields the differ tracks — so
 * dropping the legacy descriptions[] array made check and fix text changes
 * invisible to it, not merely absent from the output.
 */
function normalizeDescriptions(control: V1Control): Record<string, unknown>[] {
  const legacy: Record<string, unknown>[] = [];
  for (const raw of Array.isArray(control.descriptions) ? control.descriptions : []) {
    const d = plainObject(raw);
    if (!d) continue;
    if (typeof d.label !== 'string' || d.label === '') continue;
    legacy.push({ label: d.label, data: typeof d.data === 'string' ? d.data : '' });
  }

  // A legacy `default` entry is the source's own prose and wins over `desc`;
  // overwriting it from `desc` dropped that prose whenever the two differed.
  // Matches ensureDefaultDescription, which the converter uses.
  if (legacy.some((d) => d.label === 'default')) return legacy;
  return [{ label: 'default', data: typeof control.desc === 'string' ? control.desc : '' }, ...legacy];
}

function normalizeControl(control: V1Control): Record<string, unknown> {
  const v1Results = control.results ?? [];
  const results = v1Results.map(normalizeResult);

  return {
    id: control.id,
    title: control.title,
    descriptions: normalizeDescriptions(control),
    impact: control.impact,
    tags: control.tags ?? {},
    refs: normalizeRefs(control.refs),
    code: control.code,
    sourceLocation: normalizeSourceLocation(control),
    results,
  };
}

/**
 * Map InSpec v1 result status values to HDF v2 Result_Status enum values.
 *
 * InSpec v1 uses: "passed", "failed", "skipped", "error"
 * HDF v2 uses: "passed", "failed", "notApplicable", "notReviewed", "error"
 *
 * "skipped" in InSpec means the test was not executed (typically because a
 * `describe.one_of` condition was not met, or `only_if` excluded it).
 * This maps to "notReviewed" in HDF v2 — the requirement was not assessed.
 */
function normalizeResultStatus(v1Status: string): string {
  switch (v1Status) {
    case 'skipped':
      return 'notReviewed';
    default:
      return v1Status;
  }
}

/**
 * Normalize a timestamp string to RFC 3339 / ISO 8601 date-time format.
 *
 * InSpec v1 uses formats like "2017-09-22 14:12:15 -0400" which are not valid
 * RFC 3339. This function attempts to parse and re-format such timestamps.
 * If parsing fails, the original string is returned as-is.
 */
function normalizeTimestamp(timestamp: string): string {
  // Already valid ISO 8601 (contains 'T')
  if (timestamp.includes('T')) {
    return timestamp;
  }

  // Parse InSpec format ("YYYY-MM-DD HH:MM:SS +HHMM") via the shared helper,
  // which reads a zone-less value as UTC rather than host-local.
  const parsed = parseTimestamp(timestamp);
  if (parsed) {
    return parsed.toISOString();
  }

  return timestamp;
}

function normalizeResult(result: V1Result): Record<string, unknown> {
  const rawStartTime = result.start_time ?? result.startTime ?? '';
  const normalized: Record<string, unknown> = {
    status: normalizeResultStatus(result.status),
    codeDesc: result.code_desc ?? result.codeDesc ?? '',
    startTime: rawStartTime ? normalizeTimestamp(rawStartTime) : rawStartTime,
  };

  // Only include optional fields when they have values
  const runTime = result.run_time ?? result.runTime;
  if (runTime !== undefined) {
    normalized['runTime'] = runTime;
  }
  if (result.message !== undefined) {
    normalized['message'] = result.message;
  }

  return normalized;
}
