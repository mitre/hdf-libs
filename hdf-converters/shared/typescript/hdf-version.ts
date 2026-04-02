/**
 * HDF version transform router.
 *
 * Converts between HDF schema versions (v1 ↔ v2) using a registry of
 * transform functions. Adding new versions means registering new pairs —
 * the router logic does not change.
 */

export type HDFVersionTransform = (input: string) => string;

const hdfTransforms = new Map<string, HDFVersionTransform>();

// Register v1 ↔ v2 transforms
hdfTransforms.set('1→2', upgradeV1ToV2);
hdfTransforms.set('2→1', downgradeV2ToV1);

/**
 * Transform HDF data between schema versions.
 * Returns the input unchanged when fromVersion === toVersion.
 * Throws for unknown version pairs.
 */
export function transformHDF(input: string, fromVersion: string, toVersion: string): string {
  if (fromVersion === toVersion) return input;

  const key = `${fromVersion}→${toVersion}`;
  const transform = hdfTransforms.get(key);
  if (!transform) {
    throw new Error(`No HDF transform registered for ${fromVersion} → ${toVersion}`);
  }

  return transform(input);
}

/**
 * Detect HDF version from structural markers.
 * Returns "1" or "2", or throws if unrecognizable.
 */
export function detectHDFVersion(input: string): string {
  const obj = JSON.parse(input) as Record<string, unknown>;

  if ('profiles' in obj && 'platform' in obj) return '1';
  if ('baselines' in obj && 'components' in obj) return '2';

  throw new Error('Cannot determine HDF version: missing expected structural fields');
}

// --- v1 → v2 upgrade ---

interface V1Results {
  version?: string;
  platform?: { name: string; release?: string; target_id?: string };
  profiles?: V1Profile[];
  statistics?: { duration?: number };
}

interface V1Profile {
  name: string;
  version?: string;
  title?: string;
  maintainer?: string;
  summary?: string;
  license?: string;
  copyright?: string;
  copyright_email?: string;
  sha256?: string;
  groups?: Array<{ id: string; title?: string; controls?: string[] }>;
  controls?: V1Control[];
  depends?: Array<Record<string, unknown>>;
  supports?: Array<Record<string, unknown>>;
  attributes?: Array<Record<string, unknown>>;
}

interface V1Control {
  id: string;
  title?: string;
  desc?: string;
  descriptions?: Array<{ label: string; data: string }>;
  impact: number;
  tags?: Record<string, unknown>;
  code?: string;
  source_location?: { ref?: string; line?: number };
  results?: V1Result[];
  refs?: unknown[];
  waiver_data?: Record<string, unknown>;
}

interface V1Result {
  status: string;
  code_desc?: string;
  run_time?: number;
  start_time?: string;
  message?: string;
  exception?: string;
  backtrace?: string[];
  skip_message?: string;
}

function upgradeV1ToV2(input: string): string {
  const v1 = JSON.parse(input) as V1Results;

  const baselines = (v1.profiles ?? []).map(convertProfileToBaseline);

  const components: Record<string, unknown>[] = [];
  if (v1.platform) {
    components.push({
      type: 'host',
      name: v1.platform.name,
      ...(v1.platform.release ? { osVersion: v1.platform.release } : {}),
      labels: {},
    });
  }

  const v2: Record<string, unknown> = {
    baselines,
    components,
    statistics: v1.statistics ?? {},
  };

  return JSON.stringify(v2, null, 2);
}

function convertProfileToBaseline(p: V1Profile): Record<string, unknown> {
  return {
    name: p.name,
    ...(p.version ? { version: p.version } : {}),
    ...(p.title ? { title: p.title } : {}),
    ...(p.maintainer ? { maintainer: p.maintainer } : {}),
    ...(p.summary ? { summary: p.summary } : {}),
    ...(p.license ? { license: p.license } : {}),
    ...(p.copyright ? { copyright: p.copyright } : {}),
    ...(p.copyright_email ? { copyrightEmail: p.copyright_email } : {}),
    supports: p.supports ?? [],
    groups: (p.groups ?? []).map(g => ({
      id: g.id,
      ...(g.title ? { title: g.title } : {}),
      requirements: g.controls ?? [],
    })),
    requirements: (p.controls ?? []).map(convertControlToRequirement),
    depends: p.depends ?? [],
    inputs: (p.attributes ?? []).map(a => ({ ...a })),
  };
}

function convertControlToRequirement(c: V1Control): Record<string, unknown> {
  const descriptions = c.descriptions ?? [];
  if (descriptions.length === 0 && c.desc) {
    descriptions.push({ label: 'default', data: c.desc });
  }
  if (descriptions.length === 0) {
    descriptions.push({ label: 'default', data: '' });
  }

  return {
    id: c.id,
    ...(c.title ? { title: c.title } : {}),
    impact: c.impact,
    tags: c.tags ?? {},
    descriptions,
    results: (c.results ?? []).map(convertV1Result),
    ...(c.code ? { code: c.code } : {}),
    ...(c.source_location ? {
      sourceLocation: {
        ...(c.source_location.ref ? { ref: c.source_location.ref } : {}),
        ...(c.source_location.line !== undefined ? { line: c.source_location.line } : {}),
      },
    } : {}),
    refs: c.refs ?? [],
  };
}

const statusMap: Record<string, string> = {
  passed: 'passed',
  failed: 'failed',
  error: 'error',
  not_applicable: 'notApplicable',
  not_reviewed: 'notReviewed',
  skipped: 'notReviewed',
};

function convertV1Result(r: V1Result): Record<string, unknown> {
  return {
    status: statusMap[r.status] ?? r.status,
    codeDesc: r.code_desc ?? '',
    startTime: r.start_time ?? new Date().toISOString(),
    ...(r.run_time !== undefined ? { runTime: r.run_time } : {}),
    ...(r.message ? { message: r.message } : {}),
    ...(r.exception ? { exception: r.exception } : {}),
    ...(r.backtrace?.length ? { backtrace: r.backtrace } : {}),
  };
}

// --- v2 → v1 downgrade (lossy) ---

function downgradeV2ToV1(input: string): string {
  const v2 = JSON.parse(input) as Record<string, unknown>;

  const targets = v2.components as Array<Record<string, unknown>> ?? [];
  const baselines = v2.baselines as Array<Record<string, unknown>> ?? [];
  const statistics = v2.statistics as Record<string, unknown> ?? {};

  const platform: Record<string, unknown> = { name: '' };
  if (targets.length > 0) {
    const t = targets[0]!;
    platform.name = t.name ?? '';
    if (t.osVersion) platform.release = t.osVersion;
    if (t.name) platform.target_id = t.name;
  }

  const profiles = baselines.map(convertBaselineToV1Profile);

  const v1 = { platform, profiles, statistics };
  return JSON.stringify(v1, null, 2);
}

function convertBaselineToV1Profile(b: Record<string, unknown>): Record<string, unknown> {
  const requirements = b.requirements as Array<Record<string, unknown>> ?? [];
  const groups = b.groups as Array<Record<string, unknown>> ?? [];

  return {
    name: b.name ?? '',
    ...(b.version ? { version: b.version } : {}),
    ...(b.title ? { title: b.title } : {}),
    ...(b.maintainer ? { maintainer: b.maintainer } : {}),
    ...(b.summary ? { summary: b.summary } : {}),
    ...(b.license ? { license: b.license } : {}),
    ...(b.copyright ? { copyright: b.copyright } : {}),
    ...(b.copyrightEmail ? { copyright_email: b.copyrightEmail } : {}),
    groups: groups.map(g => ({
      id: g.id,
      ...(g.title ? { title: g.title } : {}),
      controls: g.requirements ?? [],
    })),
    controls: requirements.map(convertRequirementToV1Control),
    depends: b.depends ?? [],
  };
}

const reverseStatusMap: Record<string, string> = {
  passed: 'passed',
  failed: 'failed',
  error: 'error',
  notApplicable: 'not_applicable',
  notReviewed: 'not_reviewed',
};

function convertRequirementToV1Control(r: Record<string, unknown>): Record<string, unknown> {
  const descriptions = r.descriptions as Array<{ label: string; data: string }> ?? [];
  const results = r.results as Array<Record<string, unknown>> ?? [];

  let desc: string | undefined;
  for (const d of descriptions) {
    if (d.label === 'default') { desc = d.data; break; }
  }

  return {
    id: r.id,
    ...(r.title ? { title: r.title } : {}),
    ...(desc !== undefined ? { desc } : {}),
    impact: r.impact ?? 0,
    tags: r.tags ?? {},
    descriptions: descriptions.map(d => ({ label: d.label, data: d.data })),
    results: results.map(res => ({
      status: reverseStatusMap[res.status as string] ?? res.status,
      code_desc: res.codeDesc ?? '',
      ...(res.startTime ? { start_time: res.startTime } : {}),
      ...(res.runTime !== undefined ? { run_time: res.runTime } : {}),
      ...(res.message ? { message: res.message } : {}),
      ...(res.exception ? { exception: res.exception } : {}),
      ...((res.backtrace as unknown[])?.length ? { backtrace: res.backtrace } : {}),
    })),
    ...(r.code ? { code: r.code } : {}),
    ...(r.sourceLocation ? {
      source_location: {
        ...((r.sourceLocation as Record<string, unknown>).ref ? { ref: (r.sourceLocation as Record<string, unknown>).ref } : {}),
        ...((r.sourceLocation as Record<string, unknown>).line !== undefined ? { line: (r.sourceLocation as Record<string, unknown>).line } : {}),
      },
    } : {}),
    refs: r.refs ?? [],
  };
}
