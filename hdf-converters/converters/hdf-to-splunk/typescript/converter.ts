import { parseJSON } from '@mitre/hdf-utilities';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  CommonMeta,
  ReportMeta,
  SplunkControl,
  SplunkData,
  SplunkProfile,
  SplunkReport,
} from './types.js';

const GENERATOR_NAME = 'hdf-to-splunk';
const HDF_SPLUNK_SCHEMA_VERSION = '1.1';
const DEFAULT_FILENAME = 'hdf-results.json';
const SUBTYPE_HEADER = 'header';
const SUBTYPE_PROFILE = 'profile';
const SUBTYPE_CONTROL = 'control';
const FILETYPE_EVALUATION = 'evaluation';

/**
 * ConvertHdfToSplunk parses HDF Results JSON and returns the Splunk records
 * payload as JSON. Output shape: { reports, profiles, controls }.
 *
 * The output's meta.filename field is the placeholder "hdf-results.json";
 * uploaders should rewrite it at submission time when the real filename is
 * known.
 *
 * Throws on invalid JSON or HDF docs with no baselines (which violates the
 * HDF schema's baselines.minItems = 1 invariant).
 */
export function convertHdfToSplunk(input: string): string {
  validateInputSize(input, GENERATOR_NAME);
  if (!input?.trim()) {
    throw new Error(`${GENERATOR_NAME}: empty input`);
  }

  const doc = parseJSON<ParsedDoc>(input);
  if (!Array.isArray(doc.baselines) || doc.baselines.length === 0) {
    throw new Error(`${GENERATOR_NAME}: HDF document contains no baselines`);
  }

  const guid = newGuid();
  const data: SplunkData = {
    reports: [buildReport(doc, guid)],
    profiles: doc.baselines.map((b) => buildProfile(b, guid)),
    controls: doc.baselines.flatMap((b) =>
      (b.requirements ?? []).map((r) => buildControl(r, b, doc, guid)),
    ),
  };
  return JSON.stringify(data, null, 2);
}

// ---- parsed input shape ----

interface ParsedDoc {
  baselines: ParsedBaseline[];
  tool?: { name?: string; version?: string };
  generator?: { version?: string };
  extensions?: Record<string, unknown>;
  statistics?: unknown;
}

interface ParsedBaseline {
  name: string;
  title?: string;
  summary?: string;
  version?: string;
  copyright?: string;
  copyrightEmail?: string;
  maintainer?: string;
  license?: string;
  status?: string;
  parentBaseline?: string;
  resultsChecksum?: { value?: string; checksum?: string };
  integrity?: { value?: string; checksum?: string };
  supports?: unknown[];
  depends?: unknown[];
  inputs?: unknown[];
  groups?: unknown[];
  requirements: ParsedRequirement[];
}

interface ParsedRequirement {
  id: string;
  title?: string;
  code?: string;
  impact: number;
  tags?: Record<string, unknown>;
  descriptions?: { label: string; data: string }[];
  refs?: unknown[];
  sourceLocation?: unknown;
  results: { status: string; [k: string]: unknown }[];
  disposition?: string;
}

// ---- builders ----

function buildReport(doc: ParsedDoc, guid: string): SplunkReport {
  const r: SplunkReport = {
    meta: makeMeta<ReportMeta>(guid, SUBTYPE_HEADER),
    profiles: [],
    platform: {
      name: doc.tool?.name ?? '',
      release: doc.tool?.version ?? '',
    },
  };
  if (doc.statistics !== undefined) r.statistics = doc.statistics;
  if (doc.extensions && Object.keys(doc.extensions).length > 0) {
    r.passthrough = doc.extensions;
  }
  if (doc.generator?.version) r.version = doc.generator.version;
  return r;
}

function buildProfile(b: ParsedBaseline, guid: string): SplunkProfile {
  const sha = profileSha(b);
  const p: SplunkProfile = {
    meta: {
      ...makeMeta<CommonMeta>(guid, SUBTYPE_PROFILE),
      is_baseline: b.parentBaseline === undefined || b.parentBaseline === null,
      profile_sha256: sha,
    },
    sha256: sha,
    name: b.name,
    controls: [],
    supports: b.supports ?? [],
    depends: b.depends ?? [],
    attributes: b.inputs ?? [],
    groups: b.groups ?? [],
  };
  if (b.summary !== undefined) p.summary = b.summary;
  if (b.copyright !== undefined) p.copyright = b.copyright;
  if (b.maintainer !== undefined) p.maintainer = b.maintainer;
  if (b.copyrightEmail !== undefined) p.copyright_email = b.copyrightEmail;
  if (b.version !== undefined) p.version = b.version;
  if (b.license !== undefined) p.license = b.license;
  if (b.title !== undefined) p.title = b.title;
  if (b.parentBaseline !== undefined && b.parentBaseline !== null) {
    p.parent_profile = b.parentBaseline;
  }
  if (b.status !== undefined) p.status = b.status;
  return p;
}

function buildControl(
  req: ParsedRequirement,
  b: ParsedBaseline,
  doc: ParsedDoc,
  guid: string,
): SplunkControl {
  const c: SplunkControl = {
    meta: {
      ...makeMeta<CommonMeta>(guid, SUBTYPE_CONTROL),
      status: foldStatus(req.results ?? []),
      profile_sha256: profileSha(b),
      is_baseline: b.parentBaseline === undefined || b.parentBaseline === null,
      is_waived: req.disposition === 'waiver',
      overlay_depth: overlayDepth(b, doc),
    },
    code: req.code ?? '',
    desc: defaultDescription(req.descriptions ?? []),
    descriptions: flattenDescriptions(req.descriptions ?? []),
    id: req.id,
    impact: req.impact,
    refs: req.refs ?? [],
    tags: req.tags ?? {},
    results: req.results ?? [],
  };
  if (req.title !== undefined) c.title = req.title;
  if (req.sourceLocation !== undefined) c.source_location = req.sourceLocation;
  return c;
}

// ---- helpers ----

function makeMeta<T extends CommonMeta>(guid: string, subtype: string): T {
  return {
    guid,
    filename: DEFAULT_FILENAME,
    filetype: FILETYPE_EVALUATION,
    subtype,
    hdf_splunk_schema: HDF_SPLUNK_SCHEMA_VERSION,
  } as T;
}

function profileSha(b: ParsedBaseline): string {
  return (
    b.resultsChecksum?.value ??
    b.resultsChecksum?.checksum ??
    b.integrity?.value ??
    b.integrity?.checksum ??
    ''
  );
}

// foldStatus collapses one requirement's per-result statuses into the worst.
// Order (worst → best): error > failed > notReviewed > skipped > passed > notApplicable.
export function foldStatus(results: { status: string }[]): string {
  if (results.length === 0) return 'notReviewed';
  const rank: Record<string, number> = {
    error: 5,
    failed: 4,
    notReviewed: 3,
    skipped: 2,
    passed: 1,
    notApplicable: 0,
  };
  let worst = results[0]?.status ?? 'notReviewed';
  for (let i = 1; i < results.length; i++) {
    const s = results[i]?.status;
    if (s && (rank[s] ?? -1) > (rank[worst] ?? -1)) worst = s;
  }
  return worst;
}

function overlayDepth(b: ParsedBaseline, doc: ParsedDoc): number {
  let depth = 1;
  let current = b;
  const visited = new Set<string>([current.name]);
  while (current.parentBaseline) {
    const parentName = current.parentBaseline;
    if (visited.has(parentName)) break;
    visited.add(parentName);
    const parent = doc.baselines.find((x) => x.name === parentName);
    if (!parent) break;
    depth++;
    current = parent;
  }
  return depth;
}

function defaultDescription(descs: { label: string; data: string }[]): string {
  const def = descs.find((d) => d.label === 'default');
  return def?.data ?? '';
}

function flattenDescriptions(
  descs: { label: string; data: string }[],
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const d of descs) out[d.label] = d.data;
  return out;
}

// newGuid returns a 16-byte random identifier in UUIDv4 hex shape
// (8-4-4-4-12). No claims of UUIDv4 conformance — Splunk treats it as a
// string identifier. Uses Web Crypto where available, falls back to
// node:crypto.
function newGuid(): string {
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    /* v8 ignore next 3 -- Node 19+ + modern browsers have Web Crypto by default; this path is defensive */
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require('node:crypto');
    nodeCrypto.randomFillSync(bytes);
  }
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}
