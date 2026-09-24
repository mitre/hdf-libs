// Requirements query engine — the TypeScript peer of hdf-engine/go/filter.go.
// A pure filter(results, options) with no shared mutable state, kept at
// behavioural parity with the Go implementation (see test/query.test.ts, which
// runs both over the same fixture).

import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';
import { governingStatusOverrideIndex, parseTimestamp } from '@mitre/hdf-utilities';
import { deriveSeverity } from './compliance.js';
import { effectiveImpactOf, overrideInputs } from './effective.js';
import { normalizeKey, normalizeFilterValue } from './vocabulary.js';
import { safeGlobMatch } from './safematch.js';

/**
 * FilterOptions configures a requirements query. Every filter input arrives here;
 * distinct filters combine with AND, repeated values within a filter with OR.
 * statusOf resolves a requirement's display status, injected so the engine stays
 * agnostic to the caller's status-string convention (undefined → empty status).
 */
export interface FilterOptions {
  status?: string[];
  severity?: string[];
  /**
   * Compares the EFFECTIVE impact — the governing non-expired impact override's
   * value, else the requirement's own.
   */
  impact?: string;
  /**
   * Compares the requirement's own impact, ignoring overrides. It exists because
   * impact resolves them: the governance policy "an override may not move a
   * critical below 0.7" needs both scores, and no other key reaches the
   * unadjusted one.
   */
  rawImpact?: string;
  cci?: string[];
  nist?: string[];
  id?: string;
  tag?: string[];
  search?: string;
  baseline?: string;
  /**
   * The TYPE of the override that governs the requirement (waiver,
   * falsePositive, riskAdjustment, …), OR across values. Resolved through the
   * same governing-override rule effective status uses rather than read from the
   * stored disposition field, which is an output cache.
   */
  disposition?: string[];
  /**
   * Remediation-plan validity: 'valid' for a requirement carrying a POA&M still
   * in force, 'none-valid' for one carrying none, an empty list, or only lapsed
   * ones. Absence and expiry are one concept on purpose.
   */
  poams?: string;
  /** RFC3339 reference clock for expiry; undefined means now. */
  now?: string;
  limit?: number;
  count?: boolean;
  statusOf?: (control: EvaluatedRequirement) => string;
}

/**
 * A single query result row. baselineIndex and index are the match's position in
 * the result set (results.baselines[baselineIndex].requirements[index]) and are
 * the only unique identity a match has: baseline names repeat in shipped
 * converter output and requirement ids repeat within a baseline, so (baseline,
 * id) is not a key. Address the source requirement by position, never by name.
 */
export interface Match {
  id: string;
  title: string;
  status: string;
  impact: number;
  severity: string;
  baseline: string;
  baselineIndex: number;
  index: number;
}

type FilterFunc = (control: EvaluatedRequirement, status: string, severity: string) => boolean;

/**
 * filter returns the requirements across the result set's baselines that satisfy
 * options. Applies to requirement collections (results/baseline documents); the
 * calling adapter rejects document types that carry no requirements.
 */
export function filter(results: HDFResults, options: FilterOptions): Match[] {
  const filters = buildFilters(options);
  const matches: Match[] = [];

  for (const [baselineIndex, baseline] of (results.baselines ?? []).entries()) {
    if (options.baseline && !matchesGlob(baseline.name, options.baseline)) {
      continue;
    }
    for (const [index, control] of (baseline.requirements ?? []).entries()) {
      if (options.limit && options.limit > 0 && matches.length >= options.limit && !options.count) {
        return matches;
      }

      const status = options.statusOf ? options.statusOf(control) : '';
      // Explicit STIG severity wins; impact-derived only as a fallback — the
      // canonical rule shared with the compliance counts (deriveSeverity), so
      // query rows and compliance never disagree on a requirement's severity.
      // Effective impact for the same reason the impact filter uses it: a
      // governing riskAdjustment moves the requirement into the band it was
      // re-scored into, and filter is an override-aware surface.
      const impact = effectiveImpactOf(control, options.now);
      const severity = deriveSeverity(impact, control.severity ?? null);

      if (!applyFilters(control, status, severity, filters)) {
        continue;
      }

      matches.push({
        id: control.id,
        title: control.title ?? '',
        status,
        // The effective impact, for the same reason status carries the
        // effective status and a Match has no raw twin of either.
        impact,
        severity,
        baseline: baseline.name,
        baselineIndex,
        index,
      });
    }
  }
  return matches;
}

function buildFilters(options: FilterOptions): FilterFunc[] {
  const filters: FilterFunc[] = [];

  // Compared through normalizeKey so the CLI's display spelling and the schema's
  // camelCase are one value: a filter copied from `hdf query` and a rule written
  // against the schema must select the same requirements.
  if (options.status && options.status.length > 0) {
    const statuses = options.status.map((s) => normalizeKey(normalizeFilterValue('status', s)));
    // BOTH sides go through the same alias map: the injected resolver may speak
    // the CLI's display vocabulary while the spec speaks the schema's.
    filters.push((_c, s) => statuses.includes(normalizeKey(normalizeFilterValue('status', s))));
  }

  // Normalized the same way, and through the alias map as well, so the pre-3.7
  // 'none' spelling keeps naming the informational severity on every surface
  // rather than only in the CLI.
  if (options.severity && options.severity.length > 0) {
    const severities = options.severity.map((s) => normalizeKey(normalizeFilterValue('severity', s)));
    filters.push((_c, _s, severity) =>
      severities.includes(normalizeKey(normalizeFilterValue('severity', severity)))
    );
  }

  // Disposition (OR across values). A requirement with no governing override
  // matches nothing, which is what makes "waived" and "not waived" opposites.
  if (options.disposition && options.disposition.length > 0) {
    const wanted = options.disposition.map((d) => normalizeKey(normalizeFilterValue('disposition', d)));
    filters.push((c) => {
      const governing = governingDisposition(c, options.now);
      return governing !== '' && wanted.includes(normalizeKey(normalizeFilterValue('disposition', governing)));
    });
  }

  // POA&M validity. An unrecognized value matches NOTHING rather than silently
  // degrading, matching the impact filter's posture — callers validate with
  // validPoamFilter and reject before filtering.
  if (options.poams) {
    const wantValid = poamFilterWantsValid(options.poams);
    filters.push((c) => wantValid !== undefined && hasValidPoam(c, options.now) === wantValid);
  }

  // Compared against EFFECTIVE impact, so a governing riskAdjustment is
  // honoured. Status has resolved overrides all along; an impact filter that
  // ignored a formal re-score was the same amendments-blindness in the field
  // nobody looked at.
  if (options.impact) {
    const [op, val] = parseImpactFilter(options.impact);
    filters.push((c) => compareImpact(effectiveImpactOf(c, options.now), op, val));
  }

  // The unadjusted twin, same grammar and same safe-degradation.
  if (options.rawImpact) {
    const [op, val] = parseImpactFilter(options.rawImpact);
    filters.push((c) => compareImpact(c.impact, op, val));
  }

  if (options.cci && options.cci.length > 0) {
    const ccis = options.cci.map((c) => c.toUpperCase());
    filters.push((c) => ccis.some((cci) => tagContains(c.tags, 'cci', cci)));
  }

  if (options.nist && options.nist.length > 0) {
    const nist = options.nist;
    filters.push((c) => nist.some((n) => tagMatchesGlob(c.tags, 'nist', n)));
  }

  if (options.id) {
    const id = options.id;
    filters.push(
      (c) =>
        tagContains(c.tags, 'stig_id', id) ||
        tagContains(c.tags, 'gid', id) ||
        tagContains(c.tags, 'gtitle', id) ||
        c.id === id,
    );
  }

  if (options.tag && options.tag.length > 0) {
    const tagFilters: { key: string; value: string }[] = [];
    for (const t of options.tag) {
      const idx = t.indexOf(':');
      if (idx >= 0) {
        tagFilters.push({ key: t.slice(0, idx), value: t.slice(idx + 1) });
      }
    }
    if (tagFilters.length > 0) {
      filters.push((c) => tagFilters.some((tf) => tagMatchesGlob(c.tags, tf.key, tf.value)));
    }
  }

  if (options.search) {
    const search = options.search.toLowerCase();
    filters.push((c) => {
      if (c.id.toLowerCase().includes(search)) return true;
      if (c.title && c.title.toLowerCase().includes(search)) return true;
      for (const desc of c.descriptions ?? []) {
        if (desc.data.toLowerCase().includes(search)) return true;
      }
      return false;
    });
  }

  return filters;
}

function applyFilters(
  control: EvaluatedRequirement,
  status: string,
  severity: string,
  filters: FilterFunc[],
): boolean {
  return filters.every((f) => f(control, status, severity));
}

// DECIMAL_FLOAT is the shared impact-filter operand grammar — a plain decimal:
// optional sign, digits with an optional fraction (or a leading-dot fraction),
// optional decimal exponent. It excludes the forms JS Number() accepts but that
// make no sense as a 0.0–1.0 threshold and diverge from Go strconv.ParseFloat:
// hex/binary/octal integers (0x1f→31, 0b101→5, 0o17→15) and Infinity. The Go
// engine applies the identical pattern so a filter is accepted or rejected the
// same in both languages (bead 4908.15).
const DECIMAL_FLOAT = /^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/;

// parseDecimal parses a plain-decimal operand, returning null for anything
// outside the shared grammar (including overflow to Infinity, e.g. '1e400', so
// Go's ParseFloat ErrRange rejection is mirrored).
function parseDecimal(s: string): number | null {
  if (!DECIMAL_FLOAT.test(s)) return null;
  const v = Number(s);
  return Number.isFinite(v) ? v : null;
}

// An invalid operand safe-degrades to ('=', NaN), which compareImpact treats as
// matching NOTHING — mirroring the Go engine's `return ok && compareImpact(...)`.
// It must never coerce to ('=', 0), which silently returns confidently-wrong
// impact==0 rows for a typo'd or garbage filter.
export function parseImpactFilter(f: string): [string, number] {
  const trimmed = f.trim();
  for (const op of ['>=', '<=', '>', '<', '=']) {
    if (trimmed.startsWith(op)) {
      const v = parseDecimal(trimmed.slice(op.length).trim());
      return v === null ? ['=', NaN] : [op, v];
    }
  }
  const v = parseDecimal(trimmed);
  return v === null ? ['=', NaN] : ['=', v];
}

export function compareImpact(impact: number, op: string, val: number): boolean {
  switch (op) {
    case '>':
      return impact > val;
    case '>=':
      return impact >= val;
    case '<':
      return impact < val;
    case '<=':
      return impact <= val;
    case '=':
      return impact === val;
    default:
      return false;
  }
}

export function tagContains(tags: Record<string, unknown>, key: string, value: string): boolean {
  const tagVal = tags?.[key];
  if (tagVal === undefined) {
    return false;
  }
  const want = value.toLowerCase();
  if (typeof tagVal === 'string') {
    return tagVal.toLowerCase() === want;
  }
  if (Array.isArray(tagVal)) {
    return tagVal.some((item) => typeof item === 'string' && item.toLowerCase() === want);
  }
  return false;
}

export function tagMatchesGlob(tags: Record<string, unknown>, key: string, pattern: string): boolean {
  const tagVal = tags?.[key];
  if (tagVal === undefined) {
    return false;
  }
  if (typeof tagVal === 'string') {
    return safeGlobMatch(tagVal, pattern);
  }
  if (Array.isArray(tagVal)) {
    return tagVal.some((item) => typeof item === 'string' && safeGlobMatch(item, pattern));
  }
  return false;
}

/** matchesGlob reports whether s matches the glob pattern (case-insensitive). */
export function matchesGlob(s: string, pattern: string): boolean {
  return safeGlobMatch(s, pattern);
}

/**
 * The closed vocabulary the disposition filter accepts: the schema's
 * Override_Type enum. A value outside it can only ever match nothing, which
 * would report a clean run over a filter the caller believed was applied.
 * Parity: DispositionValues in go/filter.go, pinned by the shared case table.
 * Membership is not pinned to the schema: an eighth override type would be
 * silently unfilterable in both languages until someone adds it here.
 */
export const DISPOSITION_VALUES = [
  'waiver',
  'attestation',
  'poam',
  'inherited',
  'falsePositive',
  'riskAdjustment',
  'operationalRequirement',
] as const;

/**
 * Reports whether s names an override type. Callers validate with this and
 * reject, rather than letting a typo match nothing and pass — the same contract
 * validPoamFilter provides for the other amendment filter.
 */
// Re-exported from vocabulary.ts, where all four validators share one canonical()
// rather than this one inferring "is an alias" from "the normalizer changed it".
export { validDisposition } from './vocabulary.js';

/**
 * The two values the poams filter accepts. 'none-valid' covers a requirement
 * with no POA&M, with an empty list, and with only lapsed ones: a plan that has
 * expired is not a plan, and splitting the two cases would create a value whose
 * only use is to be chosen by mistake.
 */
export const POAM_VALID = 'valid';
export const POAM_NONE_VALID = 'none-valid';

/**
 * Reports whether s is a POA&M validity value the filter understands. Callers
 * validate with this and reject, rather than letting an unrecognized value match
 * nothing and pass.
 */
export function validPoamFilter(s: string): boolean {
  return poamFilterWantsValid(s) !== undefined;
}

function poamFilterWantsValid(s: string): boolean | undefined {
  switch (s.trim().toLowerCase()) {
    case POAM_VALID:
      return true;
    case POAM_NONE_VALID:
      return false;
    default:
      return undefined;
  }
}

/**
 * The type of the override that governs the requirement, or '' when none does.
 * The index comes from the shared governing-override rule — most recently
 * applied, non-expired, carrying a status — so disposition and effective status
 * can never disagree about which override is in force.
 */
function governingDisposition(control: EvaluatedRequirement, now?: string): string {
  const overrides = control.statusOverrides ?? [];
  const index = governingStatusOverrideIndex(overrideInputs(control), now);
  return index < 0 ? '' : (overrides[index]?.type ?? '');
}

/**
 * Whether the requirement carries a POA&M still in force. expiresAt is required
 * by the schema, so a POA&M always has a deadline to judge; one exactly at the
 * reference instant has passed, matching how an override's expiry is judged.
 */
// Note the inverted zero: hdfutil treats an override with no expiresAt as never
// expiring, while a POA&M without a deadline is treated as already lapsed. The
// schema requires poams[].expiresAt so it should not arise, but the two
// same-shaped fields mean opposite things when empty.
function hasValidPoam(control: EvaluatedRequirement, now?: string): boolean {
  // parseTimestamp returns null on an unparseable value; falling back to the
  // wall clock there is wrong in the other direction, so an unusable reference
  // is treated as no reference and the caller's own validation catches it.
  const parsed = now ? parseTimestamp(now) : null;
  const ref = parsed ? parsed.getTime() : Date.now();
  return (control.poams ?? []).some((poam) => new Date(poam.expiresAt).getTime() > ref);
}
