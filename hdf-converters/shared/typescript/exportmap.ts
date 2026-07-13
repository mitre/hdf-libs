/**
 * Generic, source-tool-agnostic mapping helpers shared by the HDF export
 * converters (hdf-to-ecs, hdf-to-splunk, ...).
 *
 * The export converters deliberately operate on generically-parsed JSON rather
 * than typed HDF structs, so their output can be held byte-identical with the
 * Go implementations. This module centralizes the generic accessors, the status
 * roll-up, the requirement/document field extraction, and the canonical
 * (key-sorted, HTML-unescaped) line serialization. Target-specific event shaping
 * (ECS field names, CIM field names, envelopes) stays in each converter.
 */

import { parseTimestamp } from '@mitre/hdf-utilities';
import { validateInputSize, parseHdf } from './converterutil.js';

export type Obj = Record<string, unknown>;

// --- generic JSON access ---

export function asMap(v: unknown): Obj | undefined {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : undefined;
}

export function asArr(v: unknown): unknown[] | undefined {
  return Array.isArray(v) ? v : undefined;
}

export function getStr(m: Obj | undefined, key: string): string {
  const v = m?.[key];
  return typeof v === 'string' ? v : '';
}

export function setIf(m: Obj, key: string, val: string): void {
  if (val !== '') m[key] = val;
}

export function stringSlice(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.filter((e): e is string => typeof e === 'string');
  return [];
}

// --- status roll-up ---

/** Most-significant status across a requirement's results[] (lossless). */
export function worstOfResults(req: Obj): string {
  const results = asArr(req.results) ?? [];
  const precedence = ['failed', 'error', 'passed', 'notReviewed', 'notApplicable'];
  const present = new Set<string>();
  for (const rRaw of results) {
    const r = asMap(rRaw);
    if (r) present.add(getStr(r, 'status'));
  }
  for (const s of precedence) {
    if (present.has(s)) return s;
  }
  return 'notReviewed';
}

/**
 * Whether an HDF Result_Status is a failing verdict. Only 'failed' fails;
 * 'error' is indeterminate (not a compliance failure) and every other value is
 * non-failing. Single shared definition of "failing" for the suppression axis
 * and the per-exporter outcome maps.
 */
export function isFailing(status: string): boolean {
  return status === 'failed';
}

export interface Status {
  raw: string; // worstOf(results[].status) — the RAW verdict
  effective: string; // effectiveStatus, '' when absent
  rollup: string; // effective when set, else raw
  overridden: boolean; // statusOverrides present or effectiveStatus set
  // Acceptance axis, orthogonal to the raw verdict: raw is failing but an
  // override drove the effective status non-failing (waiver / falsePositive /
  // attestation). A riskAdjustment / operationalRequirement / poam that leaves
  // effectiveStatus failing is NOT suppressed — it stays actionable, only its
  // impact is re-scored. Keyed on effective STATUS, not "any override present".
  suppressed: boolean;
}

/** Resolve the status context for a requirement. */
export function statusOf(req: Obj): Status {
  const raw = worstOfResults(req);
  const effective = getStr(req, 'effectiveStatus');
  const overrides = asArr(req.statusOverrides);
  const rollup = effective !== '' ? effective : raw;
  return {
    raw,
    effective,
    rollup,
    overridden: (overrides !== undefined && overrides.length > 0) || 'effectiveStatus' in req,
    suppressed: isFailing(raw) && !isFailing(rollup),
  };
}

// --- document / requirement field extraction ---

export function firstComponent(doc: Obj): Obj | undefined {
  const comps = asArr(doc.components);
  if (!comps || comps.length === 0) return undefined;
  return asMap(comps[0]);
}

export function firstResultStartTime(req: Obj, fallback: string): string {
  const results = asArr(req.results) ?? [];
  if (results.length > 0) {
    const st = getStr(asMap(results[0]), 'startTime');
    if (st !== '') return st;
  }
  return fallback;
}

export function defaultDescription(req: Obj): string {
  const descs = asArr(req.descriptions) ?? [];
  for (const dRaw of descs) {
    const d = asMap(dRaw);
    if (d && getStr(d, 'label') === 'default') return getStr(d, 'data');
  }
  return '';
}

export function firstRefURL(req: Obj): string {
  const refs = asArr(req.refs) ?? [];
  for (const rRaw of refs) {
    const url = getStr(asMap(rRaw), 'url');
    if (url !== '') return url;
  }
  return '';
}

/** Deterministic event id: component | baseline | control. */
export function eventID(component: Obj | undefined, baselineName: string, controlID: string): string {
  let comp = '';
  if (component) comp = getStr(component, 'componentId') || getStr(component, 'name');
  return [comp, baselineName, controlID].join('|');
}

// --- lossless hdf.* block ---

/**
 * Build the lossless hdf.* namespace shared by the export converters: promoted
 * snake_case scalars plus the full requirement sub-objects preserved verbatim.
 * `status` is the lossless results roll-up (statusOf().raw); `suppressed` is the
 * acceptance axis (statusOf().suppressed).
 */
export function buildHDFBlock(
  req: Obj,
  baseline: Obj,
  status: string,
  overridden: boolean,
  suppressed: boolean,
  generator: Obj | undefined,
  tool: Obj | undefined,
  converterVersion: string,
): Obj {
  const hdf: Obj = { status, overridden, suppressed, exporter_version: converterVersion };
  setIf(hdf, 'control_id', getStr(req, 'id'));
  setIf(hdf, 'baseline', getStr(baseline, 'name'));
  if ('effectiveStatus' in req) hdf.effective_status = req.effectiveStatus;
  if ('effectiveImpact' in req) hdf.effective_impact = req.effectiveImpact;
  if ('impact' in req) hdf.impact = req.impact;
  if ('severity' in req) hdf.severity = req.severity;
  if ('disposition' in req) hdf.disposition = req.disposition;
  const tags = asMap(req.tags);
  if (tags?.nist !== undefined) hdf.nist = tags.nist;
  if (tags?.cci !== undefined) hdf.cci = tags.cci;

  const passthrough: Record<string, string> = {
    tags: 'tags',
    cvss: 'cvss',
    cwe: 'cwe',
    epss: 'epss',
    kev: 'kev',
    affectedPackages: 'affected_packages',
    descriptions: 'descriptions',
    results: 'results',
    statusOverrides: 'status_overrides',
    poams: 'poams',
    code: 'code',
    refs: 'refs',
  };
  for (const [src, dst] of Object.entries(passthrough)) {
    if (src in req) hdf[dst] = req[src];
  }
  if (generator) hdf.generator = generator;
  if (tool) hdf.tool = tool;
  return hdf;
}

// --- canonical line serialization ---

/**
 * A numeric value that must serialize with an explicit decimal point, so a
 * whole-number renders as `10.0` rather than the integer `10`. Some consumers
 * type-check strictly (OCSF's `float_t` rejects an integer-shaped token).
 * JSON.stringify cannot emit `10.0` for a JS number, so the value is carried in
 * this wrapper (passed through canonicalize untouched) and rendered as a bare
 * numeric token by stringifyLine. Go's counterpart is encoding/json's json.Number.
 */
export class RawNumber {
  constructor(readonly token: string) {}
}

/** Wrap a number as a RawNumber whose token always bears a decimal point. */
export function floatNumber(f: number): RawNumber {
  let s = String(f);
  if (!/[.eE]/.test(s)) s += '.0';
  return new RawNumber(s);
}

// SOH (U+0001) delimits a raw numeric token inside stringifyLine's intermediate
// JSON. SOH is a control character that does not occur in HDF text, so in
// practice it never collides. The only theoretical collision is a string whose
// ENTIRE value is exactly SOH + <bare number> + SOH — unreachable from real HDF,
// which carries no raw control characters.
const RAWNUM_MARK = String.fromCharCode(1);
const RAWNUM_RE = /"\\u0001(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\\u0001"/g;

/**
 * Compare two strings by Unicode code point. This matches Go's `encoding/json`
 * key ordering, which is a bytewise comparison of the UTF-8 encoding \u2014 and UTF-8
 * byte order is identical to code-point order. JS's default Array.sort() instead
 * compares UTF-16 code units, which diverges for supplementary-plane (non-BMP)
 * characters: a lead surrogate (0xD800\u20130xDBFF) sorts before a BMP char in
 * [0xE000,0xFFFF] under UTF-16, but a non-BMP code point (\u22650x10000) sorts after
 * it under UTF-8. Iterating the string yields whole code points (surrogate pairs
 * combined), so this comparator is correct for the full Unicode range.
 */
function byCodePoint(a: string, b: string): number {
  const ai = [...a];
  const bi = [...b];
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i++) {
    const ca = ai[i]?.codePointAt(0) ?? 0;
    const cb = bi[i]?.codePointAt(0) ?? 0;
    if (ca !== cb) return ca - cb;
  }
  return ai.length - bi.length;
}

/**
 * Recursively sort object keys in Go's map-key order (bytewise UTF-8 / code
 * point) so the emitted JSON is byte-identical to Go's encoder.
 */
export function canonicalize(v: unknown): unknown {
  if (v instanceof RawNumber) return v; // preserve the wrapper; not an object to sort
  if (Array.isArray(v)) return v.map(canonicalize);
  const m = asMap(v);
  if (m) {
    const out: Obj = {};
    for (const k of Object.keys(m).sort(byCodePoint)) out[k] = canonicalize(m[k]);
    return out;
  }
  return v;
}

/**
 * Emit compact JSON matching Go's encoder byte-for-byte. A RawNumber is rendered
 * as a bare numeric token (Go's json.Number) via an SOH-delimited placeholder
 * that is stripped back to the token afterward. Go's encoding/json escapes
 * U+2028/U+2029 (JSONP safety) while JSON.stringify emits them raw, so we escape
 * them here. Key ordering is handled upstream by canonicalize (code point order).
 */
export function stringifyLine(v: unknown): string {
  return JSON.stringify(v, (_key, val) => (val instanceof RawNumber ? RAWNUM_MARK + val.token + RAWNUM_MARK : val))
    .replace(RAWNUM_RE, '$1')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

// --- shared export driver ---

/**
 * Maps one requirement (with its baseline and doc-level context) to one output
 * object. Doc-level context is supplied by the driver; per-exporter constants
 * (e.g. the converter version) are captured by the closure the exporter passes
 * in — keeping the driver target-agnostic.
 */
export type EventBuilder = (
  req: Obj,
  baseline: Obj,
  docTimestamp: string,
  tool: Obj | undefined,
  generator: Obj | undefined,
  component: Obj | undefined,
) => Obj;

/**
 * Shared entry-point driver for the HDF→SIEM exporters: runs the identical
 * prologue (validate, parse, baselines extraction, doc-level context), fans out
 * one output object per requirement via `build`, and joins the canonical NDJSON
 * lines (byte-identical with the Go `Export` driver). `converterName` prefixes
 * the missing-baselines error and drives validateInputSize.
 */
export function runExport(input: string, converterName: string, build: EventBuilder): string {
  validateInputSize(input, converterName);
  const doc = parseHdf<Obj>(input);

  const baselines = asArr(doc.baselines);
  if (!baselines) {
    throw new Error(`${converterName}: invalid HDF structure: missing baselines field`);
  }

  const docTimestamp = getStr(doc, 'timestamp');
  const tool = asMap(doc.tool);
  const generator = asMap(doc.generator);
  const component = firstComponent(doc);

  const lines: string[] = [];
  for (const bRaw of baselines) {
    const baseline = asMap(bRaw);
    if (!baseline) continue;
    const reqs = asArr(baseline.requirements) ?? [];
    for (const rRaw of reqs) {
      const req = asMap(rRaw);
      if (!req) continue;
      lines.push(stringifyLine(canonicalize(build(req, baseline, docTimestamp, tool, generator, component))));
    }
  }
  return lines.length === 0 ? '' : lines.join('\n') + '\n';
}

/**
 * The first cvss[].source that looks like a CVE id (case-insensitive "CVE-"
 * prefix), or ''. Shared by the exporters that key vulnerability identity off
 * the CVE (splunk, ocsf).
 */
export function firstCVE(cvssList: unknown[]): string {
  for (const c of cvssList) {
    const src = getStr(asMap(c), 'source');
    if (src.toUpperCase().startsWith('CVE-')) return src;
  }
  return '';
}

/**
 * Parse an HDF RFC3339 timestamp into integer epoch seconds (Splunk HEC `time`)
 * via the canonical parser, returning undefined when empty/unparseable. Integer
 * epoch keeps Go and TypeScript byte-identical.
 */
export function epochSeconds(s: string): number | undefined {
  const d = parseTimestamp(s);
  if (d === null) return undefined;
  return Math.floor(d.getTime() / 1000);
}

/**
 * Parse an HDF RFC3339 timestamp into integer epoch milliseconds (OCSF `time`)
 * via the canonical parser, returning undefined when empty/unparseable.
 */
export function epochMillis(s: string): number | undefined {
  const d = parseTimestamp(s);
  if (d === null) return undefined;
  return d.getTime();
}
