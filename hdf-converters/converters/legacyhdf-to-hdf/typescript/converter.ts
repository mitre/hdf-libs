/**
 * HDF v1.0 to v2.0 converter.
 *
 * Comprehensive transformations:
 * - Top-level: version removed, profiles → baselines, platform → components
 * - Baseline: sha256 → checksum, controls → requirements
 * - Control: source_location → sourceLocation, waiver_data → waiverData, status → effectiveStatus
 * - Results: snake_case → camelCase for all fields
 * - Overlay flattening: merge overlay/wrapper baselines so every requirement has results
 */

import { flattenOverlays } from '@mitre/hdf-parsers';
import type { HdfResults } from '@mitre/hdf-schema';
import { deriveControlTypeFromTags, validateInputSize } from '../../../shared/typescript/converterutil.js';

// ===== V1.0 Type Definitions =====

export interface V1Result {
  status: string;
  code_desc?: string;
  run_time?: number;
  start_time?: string;
  message?: string;
  exception?: string;
  backtrace?: unknown;
  resource_class?: string;
  resource_params?: string;
  resource_id?: string;
  skip_message?: string;
  [key: string]: unknown;
}

export interface V1Control {
  id: string;
  title?: string;
  desc?: string;
  descriptions?: Array<{label: string; data: string}>;
  impact: number;
  refs?: unknown[];
  tags?: Record<string, unknown>;
  code?: string;
  source_location?: {
    ref?: string;
    line?: number;
  };
  waiver_data?: Record<string, unknown>;
  results?: V1Result[];
  status?: string; // overall_status in some v1.0 variants
  [key: string]: unknown;
}

export interface V1Group {
  id: string;
  title?: string;
  controls: string[]; // Array of control IDs
  [key: string]: unknown;
}

export interface V1Dependency {
  name?: string;
  url?: string;
  path?: string;
  git?: string;
  branch?: string;
  tag?: string;
  commit?: string;
  version?: string;
  supermarket?: string;
  compliance?: string;
  status?: string;
  skip_message?: string;
  [key: string]: unknown;
}

export interface V1Profile {
  name: string;
  version?: string;
  title?: string;
  maintainer?: string;
  summary?: string;
  license?: string;
  copyright?: string;
  copyright_email?: string;
  supports?: unknown[];
  attributes?: unknown[];
  groups?: V1Group[];
  controls?: V1Control[];
  sha256?: string;
  depends?: V1Dependency[];
  parent_profile?: string;
  status?: string;
  status_message?: string;
  skip_message?: string;
  [key: string]: unknown;
}

export interface V1Platform {
  name: string;
  release?: string;
  target_id?: string;
  [key: string]: unknown;
}

export interface HDFV1Results {
  version: string;
  platform: V1Platform;
  profiles: V1Profile[];
  statistics: unknown;
  generator?: unknown;
  timestamp?: string;
  [key: string]: unknown;
}

// ===== V2.0 Type Definitions =====

export interface V2Result {
  status: string;
  codeDesc?: string;
  runTime?: number;
  startTime?: string;
  message?: string;
  exception?: string;
  backtrace?: unknown;
  resourceClass?: string;
  resourceParams?: string;
  resourceId?: string;
  skipMessage?: string;
  [key: string]: unknown;
}

export interface V2Requirement {
  id: string;
  title?: string;
  desc?: string;
  descriptions?: Array<{label: string; data: string}>;
  impact: number;
  refs?: unknown[];
  tags?: Record<string, unknown>;
  code?: string;
  sourceLocation?: {
    ref?: string;
    line?: number;
  };
  waiverData?: Record<string, unknown>;
  results?: V2Result[];
  effectiveStatus?: string;
  [key: string]: unknown;
}

export interface V2Group {
  id: string;
  title?: string;
  requirements: string[]; // Array of requirement IDs
  [key: string]: unknown;
}

export interface V2Dependency {
  name?: string;
  url?: string;
  path?: string;
  git?: string;
  branch?: string;
  tag?: string;
  commit?: string;
  version?: string;
  supermarket?: string;
  compliance?: string;
  status?: string;
  skipMessage?: string;
  [key: string]: unknown;
}

export interface V2Baseline {
  name: string;
  version?: string;
  title?: string;
  maintainer?: string;
  summary?: string;
  license?: string;
  copyright?: string;
  copyright_email?: string;
  supports?: unknown[];
  inputs?: unknown[];
  groups?: V2Group[];
  requirements?: V2Requirement[];
  checksum?: {
    algorithm: string;
    value: string;
  };
  depends?: V2Dependency[];
  parentBaseline?: string;
  status?: string;
  statusMessage?: string;
  skipMessage?: string;
  [key: string]: unknown;
}

export interface HDFV2Results {
  baselines: V2Baseline[];
  statistics: unknown;
  components?: unknown[];
  generator?: unknown;
  tool?: { name?: string; version?: string; format?: string };
  timestamp?: string;
  id?: string;
  integrity?: unknown;
  runner?: unknown;
  remediation?: unknown;
  extensions?: Record<string, unknown>;
}

// ===== Severity Helpers =====

/** Valid severity values per HDF v2.0 schema. */
const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'informational', 'none']);

/**
 * Convert tags.severity string to a valid severity value.
 * Returns null if the value is not a recognized severity.
 */
function tagSeverityToSeverity(tagSeverity: unknown): string | null {
  if (typeof tagSeverity !== 'string') return null;
  const normalized = tagSeverity.toLowerCase().trim();
  return VALID_SEVERITIES.has(normalized) ? normalized : null;
}

/**
 * Derive severity from numeric impact score.
 * Follows InSpec conventions: 0.9+ critical, 0.7+ high, 0.5+ medium, >0 low, 0 none.
 */
function impactToSeverity(impact: number): string {
  if (impact >= 0.9) return 'critical';
  if (impact >= 0.7) return 'high';
  if (impact >= 0.5) return 'medium';
  if (impact > 0) return 'low';
  return 'none';
}

// ===== Conversion Functions =====

/**
 * Normalize status values from v1.0 to v2.0 format.
 * Converts snake_case to camelCase.
 */
function normalizeStatus(status: string): string {
  const statusMap: Record<string, string> = {
    'passed': 'passed',
    'failed': 'failed',
    'error': 'error',
    'not_applicable': 'notApplicable',
    'not_reviewed': 'notReviewed',
    'skipped': 'notReviewed', // v1.0 skipped → v2.0 notReviewed
  };
  return statusMap[status] || 'notReviewed'; // unknown statuses default to notReviewed (matches Go)
}

/**
 * Compute effectiveStatus from impact and v2 results.
 * Implements InSpec enhanced outcomes precedence:
 *   impact=0 → notApplicable
 *   error > failed > passed > notApplicable > notReviewed
 *
 * See docs/design/status-determination.md for full specification.
 */
function computeEffectiveStatus(impact: number, results: V2Result[]): string {
  if (impact === 0) return 'notApplicable';
  if (results.length === 0) return 'notReviewed';

  let hasFailed = false;
  let hasPassed = false;
  let hasNotApplicable = false;

  for (const r of results) {
    switch (r.status) {
      case 'error': return 'error'; // fail-fast: highest precedence
      case 'failed': hasFailed = true; break;
      case 'passed': hasPassed = true; break;
      case 'notApplicable': hasNotApplicable = true; break;
    }
  }

  if (hasFailed) return 'failed';
  if (hasPassed) return 'passed';
  if (hasNotApplicable) return 'notApplicable';
  return 'notReviewed';
}

/**
 * Convert v1.0 result to v2.0 result.
 * Transforms snake_case field names to camelCase.
 */
function convertResult(v1Result: V1Result): V2Result {
  const v2Result: V2Result = {
    status: normalizeStatus(v1Result.status),
  };

  // Transform snake_case to camelCase
  if (v1Result.code_desc !== undefined) v2Result.codeDesc = v1Result.code_desc;
  if (v1Result.run_time !== undefined) v2Result.runTime = v1Result.run_time;
  if (v1Result.start_time !== undefined) v2Result.startTime = v1Result.start_time;
  if (v1Result.message !== undefined) v2Result.message = v1Result.message;
  if (v1Result.exception !== undefined) v2Result.exception = v1Result.exception;
  if (v1Result.backtrace !== undefined) v2Result.backtrace = v1Result.backtrace;
  if (v1Result.resource_class !== undefined) v2Result.resourceClass = v1Result.resource_class;
  if (v1Result.resource_params !== undefined) v2Result.resourceParams = v1Result.resource_params;
  if (v1Result.resource_id !== undefined) v2Result.resourceId = v1Result.resource_id;
  if (v1Result.skip_message !== undefined) v2Result.skipMessage = v1Result.skip_message;

  // Preserve any other fields
  const knownFields = new Set([
    'status', 'code_desc', 'run_time', 'start_time', 'message', 'exception',
    'backtrace', 'resource_class', 'resource_params', 'resource_id', 'skip_message'
  ]);
  for (const [key, value] of Object.entries(v1Result)) {
    if (!knownFields.has(key) && !(key in v2Result)) {
      v2Result[key] = value;
    }
  }

  return v2Result;
}

/**
 * Convert v1.0 control to v2.0 requirement.
 * Transforms field names and structure.
 */
function convertControl(v1Control: V1Control): V2Requirement {
  const v2Req: V2Requirement = {
    id: v1Control.id,
    impact: v1Control.impact,
  };

  // Copy simple fields
  if (v1Control.title !== undefined) v2Req.title = v1Control.title;
  if (v1Control.desc !== undefined) v2Req.desc = v1Control.desc;
  if (v1Control.descriptions !== undefined) v2Req.descriptions = v1Control.descriptions;
  if (v1Control.refs !== undefined) v2Req.refs = v1Control.refs;
  if (v1Control.tags !== undefined) v2Req.tags = v1Control.tags;
  if (v1Control.code !== undefined) v2Req.code = v1Control.code;

  // Transform snake_case to camelCase
  if (v1Control.source_location !== undefined) {
    v2Req.sourceLocation = v1Control.source_location;
  }
  if (v1Control.waiver_data !== undefined) {
    v2Req.waiverData = v1Control.waiver_data;
  }

  // Transform status to effectiveStatus with normalization
  if (v1Control.status !== undefined) {
    v2Req.effectiveStatus = normalizeStatus(v1Control.status);
  }

  // Transform results array
  if (v1Control.results && Array.isArray(v1Control.results)) {
    v2Req.results = v1Control.results.map(convertResult);
  }

  // Always compute effectiveStatus when not explicitly set.
  // Uses InSpec enhanced outcomes precedence:
  // impact=0 → notApplicable, error > failed > passed > notApplicable > notReviewed
  if (!v2Req.effectiveStatus) {
    v2Req.effectiveStatus = computeEffectiveStatus(v1Control.impact, v2Req.results ?? []);
  }

  // Populate severity: prefer tags.severity (preserves original STIG severity),
  // fall back to impact-derived. InSpec sets impact=0 for NA controls, losing
  // the original severity — tags.severity preserves it.
  v2Req.severity = tagSeverityToSeverity(v1Control.tags?.severity) ?? impactToSeverity(v1Control.impact);

  // Derive controlType from v1 tags.nist if present.
  const rawNist = v1Control.tags?.nist;
  if (Array.isArray(rawNist)) {
    const nistStrs = rawNist.filter((v): v is string => typeof v === 'string');
    const controlType = deriveControlTypeFromTags(nistStrs);
    if (controlType !== undefined) {
      v2Req.controlType = controlType;
    }
  }

  // verificationMethod is intentionally NOT set here. legacyhdf is a v1->v3
  // passthrough/upgrade converter; v1 HDF predates the verificationMethod
  // field, so the source carries no such signal. Stamping a value would
  // fabricate data not present in the input.

  // Preserve any other fields
  const knownFields = new Set([
    'id', 'title', 'desc', 'descriptions', 'impact', 'refs', 'tags', 'code',
    'source_location', 'waiver_data', 'results', 'status'
  ]);
  for (const [key, value] of Object.entries(v1Control)) {
    if (!knownFields.has(key) && !(key in v2Req)) {
      v2Req[key] = value;
    }
  }

  return v2Req;
}

/**
 * Convert v1.0 group to v2.0 group.
 * Renames controls array to requirements.
 */
function convertGroup(v1Group: V1Group): V2Group {
  const v2Group: V2Group = {
    id: v1Group.id,
    requirements: v1Group.controls, // Rename controls to requirements
  };

  if (v1Group.title !== undefined) {
    v2Group.title = v1Group.title;
  }

  // Preserve any other fields
  const knownFields = new Set(['id', 'title', 'controls']);
  for (const [key, value] of Object.entries(v1Group)) {
    if (!knownFields.has(key) && !(key in v2Group)) {
      v2Group[key] = value;
    }
  }

  return v2Group;
}

/**
 * Convert v1.0 dependency to v2.0 dependency.
 * Transforms snake_case to camelCase for skip_message.
 */
function convertDependency(v1Dep: V1Dependency): V2Dependency {
  const v2Dep: V2Dependency = {};

  // Copy most fields as-is
  if (v1Dep.name !== undefined) v2Dep.name = v1Dep.name;
  if (v1Dep.url !== undefined) v2Dep.url = v1Dep.url;
  if (v1Dep.path !== undefined) v2Dep.path = v1Dep.path;
  if (v1Dep.git !== undefined) v2Dep.git = v1Dep.git;
  if (v1Dep.branch !== undefined) v2Dep.branch = v1Dep.branch;
  if (v1Dep.tag !== undefined) v2Dep.tag = v1Dep.tag;
  if (v1Dep.commit !== undefined) v2Dep.commit = v1Dep.commit;
  if (v1Dep.version !== undefined) v2Dep.version = v1Dep.version;
  if (v1Dep.supermarket !== undefined) v2Dep.supermarket = v1Dep.supermarket;
  if (v1Dep.compliance !== undefined) v2Dep.compliance = v1Dep.compliance;
  if (v1Dep.status !== undefined) v2Dep.status = v1Dep.status;

  // Transform snake_case to camelCase
  if (v1Dep.skip_message !== undefined) {
    v2Dep.skipMessage = v1Dep.skip_message;
  }

  // Preserve any other fields
  const knownFields = new Set([
    'name', 'url', 'path', 'git', 'branch', 'tag', 'commit', 'version',
    'supermarket', 'compliance', 'status', 'skip_message'
  ]);
  for (const [key, value] of Object.entries(v1Dep)) {
    if (!knownFields.has(key) && !(key in v2Dep)) {
      v2Dep[key] = value;
    }
  }

  return v2Dep;
}

/**
 * Convert v1.0 profile to v2.0 baseline.
 * Transforms field names and nested structures.
 */
function convertProfile(v1Profile: V1Profile): V2Baseline {
  const v2Baseline: V2Baseline = {
    name: v1Profile.name,
  };

  // Copy simple fields
  if (v1Profile.version !== undefined) v2Baseline.version = v1Profile.version;
  if (v1Profile.title !== undefined) v2Baseline.title = v1Profile.title;
  if (v1Profile.maintainer !== undefined) v2Baseline.maintainer = v1Profile.maintainer;
  if (v1Profile.summary !== undefined) v2Baseline.summary = v1Profile.summary;
  if (v1Profile.license !== undefined) v2Baseline.license = v1Profile.license;
  if (v1Profile.copyright !== undefined) v2Baseline.copyright = v1Profile.copyright;
  if (v1Profile.copyright_email !== undefined) v2Baseline.copyright_email = v1Profile.copyright_email;
  if (v1Profile.supports !== undefined) v2Baseline.supports = v1Profile.supports;
  if (v1Profile.attributes !== undefined) v2Baseline.inputs = v1Profile.attributes;
  if (v1Profile.status !== undefined) v2Baseline.status = v1Profile.status;

  // Transform sha256 to integrity object
  if (v1Profile.sha256) {
    v2Baseline.integrity = {
      algorithm: 'sha256',
      checksum: v1Profile.sha256,
    };
  }

  // Transform snake_case to camelCase
  if (v1Profile.parent_profile !== undefined) {
    v2Baseline.parentBaseline = v1Profile.parent_profile;
  }
  if (v1Profile.status_message !== undefined) {
    v2Baseline.statusMessage = v1Profile.status_message;
  }
  if (v1Profile.skip_message !== undefined) {
    v2Baseline.skipMessage = v1Profile.skip_message;
  }

  // Transform groups (controls → requirements)
  if (v1Profile.groups && Array.isArray(v1Profile.groups)) {
    v2Baseline.groups = v1Profile.groups.map(convertGroup);
  }

  // Transform controls to requirements
  if (v1Profile.controls && Array.isArray(v1Profile.controls)) {
    v2Baseline.requirements = v1Profile.controls.map(convertControl);
  }

  // Transform depends
  if (v1Profile.depends && Array.isArray(v1Profile.depends)) {
    v2Baseline.depends = v1Profile.depends.map(convertDependency);
  }

  // Preserve any other fields
  const knownFields = new Set([
    'name', 'version', 'title', 'maintainer', 'summary', 'license', 'copyright',
    'copyright_email', 'supports', 'attributes', 'groups', 'controls', 'sha256',
    'depends', 'parent_profile', 'status', 'status_message', 'skip_message'
  ]);
  for (const [key, value] of Object.entries(v1Profile)) {
    if (!knownFields.has(key) && !(key in v2Baseline)) {
      v2Baseline[key] = value;
    }
  }

  return v2Baseline;
}

/**
 * Convert HDF v1.0 results to v2.0 format.
 *
 * Performs comprehensive transformation at all levels:
 * - Top-level: version removed, profiles → baselines, platform → components
 * - Baselines: sha256 → checksum, controls → requirements, field renaming
 * - Requirements: snake_case → camelCase, status → effectiveStatus
 * - Results: snake_case → camelCase for all fields
 *
 * @param v1Data - HDF v1.0 results object
 * @returns HDF v2.0 results object
 *
 * @example
 * ```typescript
 * const v1 = {
 *   version: "1.0.0",
 *   platform: { name: "ubuntu", release: "20.04" },
 *   profiles: [...],
 *   statistics: {...}
 * };
 * const v2 = convertV1ToV2(v1);
 * // v2 = { baselines: [...], components: [{...}], statistics: {...} }
 * ```
 */
export function convertV1ToV2(v1Data: HDFV1Results): HDFV2Results {
  validateInputSize(JSON.stringify(v1Data), 'legacyhdf-to-hdf');
  const v2: HDFV2Results = {
    baselines: (v1Data.profiles || []).map(convertProfile),
    statistics: v1Data.statistics || {},
  };

  // Transform platform to components array
  if (v1Data.platform) {
    v2.components = [
      {
        type: 'host', // v2.0 uses 'host' instead of 'system'
        id: v1Data.platform.target_id || v1Data.platform.name,
        name: v1Data.platform.name,
        ...(v1Data.platform.release && { release: v1Data.platform.release }),
        labels: {},
      },
    ];
  }

  // Copy optional fields
  if (v1Data.generator) {
    v2.generator = v1Data.generator;
  }

  v2.tool = { name: 'Heimdall Data Format v1' };

  if (v1Data.timestamp) {
    v2.timestamp = v1Data.timestamp;
  }

  // Preserve any extension fields not part of core schema
  const knownV1Fields = new Set(['version', 'platform', 'profiles', 'statistics', 'generator', 'timestamp']);
  const extensionFields: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(v1Data)) {
    if (!knownV1Fields.has(key)) {
      extensionFields[key] = value;
    }
  }

  if (Object.keys(extensionFields).length > 0) {
    v2.extensions = {
      ...extensionFields,
      v1_version: v1Data.version, // Preserve original version for tracking
    };
  }

  // Flatten overlays: merge overlay/wrapper baselines so every requirement
  // has results and consumers don't see duplicated controls (741→247 fix).
  const flat = flattenOverlays(v2 as unknown as HdfResults);
  return flat.results as unknown as HDFV2Results;
}

/**
 * Validate that data appears to be HDF v1.0 format.
 *
 * @param data - Unknown data to validate
 * @returns true if data looks like HDF v1.0
 */
export function isHDFV1(data: unknown): data is HDFV1Results {
  if (typeof data !== 'object' || data === null) {
    return false;
  }

  const obj = data as Record<string, unknown>;

  // V1.0 has version field, profiles, and platform
  return (
    typeof obj.version === 'string' &&
    Array.isArray(obj.profiles) &&
    typeof obj.platform === 'object' &&
    obj.platform !== null
  );
}
