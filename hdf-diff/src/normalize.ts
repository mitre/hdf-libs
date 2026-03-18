/**
 * Normalize InSpec exec-json v1 format to HDF v2 structure for diffing.
 *
 * V1 uses: profiles[].controls[].results[].code_desc, source_location, start_time
 * V2 uses: baselines[].requirements[].results[].codeDesc, sourceLocation, startTime
 *
 * This module detects v1 documents and converts them in-memory to v2 shape
 * so the diff engine only needs to handle one format.
 */

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

  // Preserve timestamp from statistics if available
  const statistics = doc['statistics'] as Record<string, unknown> | undefined;

  return {
    baselines,
    statistics,
    timestamp: doc['timestamp'],
  };
}

function normalizeProfile(profile: V1Profile): Record<string, unknown> {
  const controls = profile.controls ?? [];
  const requirements = controls.map(normalizeControl);

  return {
    name: profile.name,
    title: profile.title,
    version: profile.version,
    checksum: profile.sha256 ? { algorithm: 'sha256', value: profile.sha256 } : undefined,
    groups: profile.groups ?? [],
    supports: profile.supports ?? [],
    inputs: profile.attributes ?? [],
    requirements,
  };
}

function normalizeControl(control: V1Control): Record<string, unknown> {
  const v1Results = control.results ?? [];
  const results = v1Results.map(normalizeResult);

  return {
    id: control.id,
    title: control.title,
    descriptions: control.desc
      ? [{ label: 'default', data: control.desc }]
      : [],
    impact: control.impact,
    tags: control.tags ?? {},
    refs: control.refs ?? [],
    code: control.code,
    sourceLocation: control.source_location ?? control.sourceLocation,
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

  // Try to parse InSpec format: "YYYY-MM-DD HH:MM:SS +HHMM"
  const parsed = new Date(timestamp);
  if (!isNaN(parsed.getTime())) {
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
