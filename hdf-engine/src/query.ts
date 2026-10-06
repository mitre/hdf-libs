// Requirements query engine — the TypeScript peer of hdf-engine/go/filter.go.
// A pure filter(results, options) with no shared mutable state, kept at
// behavioural parity with the Go implementation (see test/query.test.ts, which
// runs both over the same fixture).

import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';
import {
  governingOverrideIndex,
  parseTimestamp,
  extractCWEIDs,
  type StatusOverrideInput,
} from '@mitre/hdf-utilities';
import { deriveSeverity } from './compliance.js';
import { effectiveImpactOf, overrideInputs } from './effective.js';
import { normalizeKey, normalizeFilterValue } from './vocabulary.js';
import { safeGlobMatch } from './safematch.js';
import { valuesActive, valuesMatch, normalizeValues, type Values, type PredicateValue } from './values.js';

/**
 * FilterOptions configures a requirements query. Every filter input arrives here;
 * distinct filters combine with AND, repeated values within a filter with OR.
 * statusOf resolves a requirement's display status, injected so the engine stays
 * agnostic to the caller's status-string convention (undefined → empty status).
 */
export interface FilterOptions {
  status?: PredicateValue;
  severity?: PredicateValue;
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
  /**
   * Compares the requirement's authoritative CVSS score, using the same
   * comparison grammar as impact. See cvssScoreOf for what "authoritative"
   * resolves to and how several CVSS entries collapse to one number.
   */
  cvss?: string;
  /**
   * Compares the EPSS exploit PROBABILITY (epss.score), not the percentile
   * rank. They share a 0-1 scale and mean very different things.
   */
  epss?: string;
  /**
   * CISA Known Exploited Vulnerabilities membership: 'true' for kev.inKev,
   * 'false' for everything else — including a requirement carrying no kev block
   * at all, which is not known-exploited either.
   */
  kev?: string;
  /**
   * Selects by CWE identifier, OR across values, matched numerically so CWE-79,
   * 'CWE 79' and cwe79 are one value. Reads the first-class cwe[] field ONLY and
   * never falls back to tags.cwe.
   */
  cwe?: PredicateValue;
  cci?: PredicateValue;
  nist?: PredicateValue;
  id?: string;
  tag?: PredicateValue;
  search?: string;
  baseline?: string;
  /**
   * Selects requirements by the labels of the baseline they sit in, as
   * `key:value`, OR across values, with the value globbable exactly as a tag
   * value is. Named for the baseline rather than `label` alone because there is
   * no requirement-level label, and because system documents carry component
   * labels that may one day want their own key.
   *
   * A label is a property of the BASELINE, so this is applied once per baseline
   * beside `baseline` rather than per requirement. A baseline carrying no labels
   * therefore matches nothing: an absent label is not a wildcard.
   * Parity: Options.BaselineLabel in go/filter.go.
   */
  baselineLabel?: PredicateValue;
  /**
   * The TYPE of the override that governs the requirement (waiver,
   * falsePositive, riskAdjustment, …), OR across values. The governing override
   * is the most recent non-expired one of ANY kind, so it may differ from the one
   * that set the status — see governingDisposition. Resolved rather than read
   * from the stored disposition field, which is an output cache.
   */
  disposition?: PredicateValue;
  /**
   * Remediation-plan validity: 'valid' for a requirement carrying a POA&M still
   * in force, 'none-valid' for one carrying none, an empty list, or only lapsed
   * ones. Absence and expiry are one concept on purpose.
   */
  poams?: string;
  /** Kind of the governing POA&M: remediation|mitigation|riskAcceptance|vendorDependency. */
  poamType?: PredicateValue;
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
export function filter(results: HDFResults, rawOptions: FilterOptions): Match[] {
  // Normalized ONCE here, so every caller — a decoded policy, the CLI, the MCP,
  // or a TypeScript consumer passing a plain array — reaches the matchers with
  // the same shape. Parity: Go reaches it by type, through Values' unmarshaller.
  const options = normalizeOptions(rawOptions);
  const filters = buildFilters(options);
  const matches: Match[] = [];

  for (const [baselineIndex, baseline] of (results.baselines ?? []).entries()) {
    if (options.baseline && !matchesGlob(baseline.name, options.baseline)) {
      continue;
    }
    if (!baselineLabelsMatch(baseline.labels, options.baselineLabel)) {
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

/** The value fields, normalized; every other option passes through unchanged. */
type NormalizedOptions = Omit<FilterOptions, (typeof VALUE_FIELDS)[number]> & {
  [K in (typeof VALUE_FIELDS)[number]]?: Values;
};

export const VALUE_FIELDS = [
  'status',
  'severity',
  'cwe',
  'cci',
  'nist',
  'tag',
  'baselineLabel',
  'disposition',
  'poamType',
] as const;

function normalizeOptions(options: FilterOptions): NormalizedOptions {
  const out: Record<string, unknown> = { ...options };
  for (const field of VALUE_FIELDS) {
    if (out[field] !== undefined) out[field] = normalizeValues(out[field]);
  }
  return out as NormalizedOptions;
}

function buildFilters(options: NormalizedOptions): FilterFunc[] {
  const filters: FilterFunc[] = [];

  // Compared through normalizeKey so the CLI's display spelling and the schema's
  // camelCase are one value: a filter copied from `hdf query` and a rule written
  // against the schema must select the same requirements.
  if (valuesActive(options.status)) {
    // BOTH sides go through the same alias map: the injected resolver may speak
    // the CLI's display vocabulary while the spec speaks the schema's.
    filters.push((_c, s) => {
      const actual = normalizeKey(normalizeFilterValue('status', s));
      return valuesMatch(options.status!, (want) => actual === normalizeKey(normalizeFilterValue('status', want)));
    });
  }

  // Normalized the same way, and through the alias map as well, so 'none' — the
  // name informational replaced in 3.7.0 — keeps selecting it on every surface,
  // not only in the CLI.
  if (valuesActive(options.severity)) {
    filters.push((_c, _s, severity) => {
      const actual = normalizeKey(normalizeFilterValue('severity', severity));
      return valuesMatch(options.severity!, (want) => actual === normalizeKey(normalizeFilterValue('severity', want)));
    });
  }

  // Disposition (OR across values). A requirement with no governing override
  // matches nothing, which is what makes "waived" and "not waived" opposites.
  if (valuesActive(options.disposition)) {
    filters.push((c) => {
      const governing = governingDisposition(c, options.now);
      // Nothing governing matches no VALUE, which is what makes an inclusive
      // predicate exclude it and a negation accept it — a failure nobody
      // adjudicated is correctly 'not waived'.
      const actual = normalizeKey(normalizeFilterValue('disposition', governing));
      return valuesMatch(
        options.disposition!,
        (want) => governing !== '' && actual === normalizeKey(normalizeFilterValue('disposition', want)),
      );
    });
  }

  if (valuesActive(options.poamType)) {
    filters.push((c) => {
      const kind = governingPoamType(c, options.now);
      return valuesMatch(options.poamType!, (want) => kind !== '' && normalizeKey(kind) === normalizeKey(want));
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

  // The vulnerability numbers, through the SAME comparison parser — a second
  // grammar would be a second thing to learn and a second thing to get wrong. A
  // requirement carrying no such score matches no comparison on it, rather than
  // defaulting to zero and matching '<5' for the wrong reason.
  if (options.cvss) {
    const [op, val] = parseImpactFilter(options.cvss);
    filters.push((c) => {
      const score = cvssScoreOf(c);
      return score !== undefined && compareImpact(score, op, val);
    });
  }
  if (options.epss) {
    const [op, val] = parseImpactFilter(options.epss);
    filters.push((c) => c.epss != null && compareImpact(c.epss.score, op, val));
  }
  if (options.kev) {
    const want = parseKevFilter(options.kev);
    filters.push((c) => want !== undefined && inKev(c) === want);
  }
  if (valuesActive(options.cwe)) {
    filters.push((c) => {
      const carried = new Set((c.cwe ?? []).flatMap((raw) => extractCWEIDs(String(raw))));
      return valuesMatch(options.cwe!, (want) => extractCWEIDs(want).some((id) => carried.has(id)));
    });
  }

  if (valuesActive(options.cci)) {
    filters.push((c) => valuesMatch(options.cci!, (want) => tagContains(c.tags, 'cci', want.toUpperCase())));
  }

  if (valuesActive(options.nist)) {
    filters.push((c) => valuesMatch(options.nist!, (want) => tagMatchesGlob(c.tags, 'nist', want)));
  }

  if (options.id) {
    const id = options.id;
    // A wildcard opts into glob matching; without one this stays the exact,
    // case-sensitive lookup it has always been. Parity: go/filter.go. The id a user
    // knows is often not the id the document carries — converters mint prefixed ids
    // (Grype/CVE-...) — while `search` reaches title, description and code and so
    // also matches a CVE merely cross-referenced in another finding's prose. A glob
    // reads only the identifier, so it can be precise about which one it names.
    if (/[*?]/.test(id)) {
      filters.push(
        (c) =>
          tagMatchesGlob(c.tags, 'stig_id', id) ||
          tagMatchesGlob(c.tags, 'gid', id) ||
          tagMatchesGlob(c.tags, 'gtitle', id) ||
          matchesGlob(c.id, id),
      );
    } else {
      filters.push(
        (c) =>
          tagContains(c.tags, 'stig_id', id) ||
          tagContains(c.tags, 'gid', id) ||
          tagContains(c.tags, 'gtitle', id) ||
          c.id === id,
      );
    }
  }

  if (valuesActive(options.tag)) {
    filters.push((c) =>
      valuesMatch(options.tag!, (want) => {
        // A colonless value names no key, so it matches nothing rather than
        // disappearing and letting the whole document through. The CLI refuses
        // one before it reaches here; this is the safe floor for any caller
        // that does not.
        const idx = want.indexOf(':');
        return idx > 0 && tagMatchesGlob(c.tags, want.slice(0, idx), want.slice(idx + 1));
      }),
    );
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

/**
 * validTag reports whether s is a tag expression at all. A value carrying no
 * colon names no key, so it can never match — and unlike the label filter, which
 * merely selected nothing, a colonless tag was DROPPED from the filter list
 * entirely, so a predicate made only of colonless values matched the whole
 * document. Refused rather than tolerated in either direction.
 * Parity: ValidTag in go/filter.go.
 */
/**
 * validKeyValue is the one "key:value with a non-empty key" test behind every
 * expression the filter takes in that shape; the exported names keep the
 * vocabulary each flag advertises. Parity: validKeyValue in go/filter.go.
 */
function validKeyValue(s: string): boolean {
  return s.indexOf(':') > 0;
}

export function validTag(s: string): boolean {
  return validKeyValue(s);
}

/**
 * The KIND of the governing POA&M, or '' when the governing entry is an override
 * or nothing governs. Resolves through the same index governingDisposition uses,
 * so disposition and poamType can never name different entries.
 *
 * Reading the GOVERNING plan rather than any carried plan is the whole point: a
 * requirement carrying a lapsed remediation under a live mitigation is governed
 * by the mitigation, and matching it on 'remediation' would let a dead plan
 * answer for a live one.
 * Parity: governingPoamType in go/filter.go.
 */
function governingPoamType(control: EvaluatedRequirement, now?: string): string {
  const overrides = control.statusOverrides ?? [];
  const entries = [...overrideInputs(control), ...poamInputs(control)];
  const index = governingOverrideIndex(entries, () => true, now);
  if (index < overrides.length) return '';
  return (control.poams ?? [])[index - overrides.length]?.type ?? '';
}

/**
 * validBaselineLabel reports whether s is a label expression at all. A value
 * carrying no colon names no key, so it can never match any document — the same
 * forever-green gate a misspelled status value produces, which is why it is
 * refused rather than allowed to select nothing.
 * Parity: ValidBaselineLabel in go/filter.go.
 */
export function validBaselineLabel(s: string): boolean {
  return validKeyValue(s);
}

/**
 * baselineLabelsMatch reports whether a baseline satisfies any of the
 * `key:value` label predicates. No predicates means every baseline qualifies;
 * otherwise one must match, so several values OR the way every other multi-value
 * filter does.
 *
 * A predicate without a colon is refused at the boundary by validBaselineLabel
 * rather than handled here, because selecting nothing and being ignored produce
 * the SAME false green under a max bound: the gate passes while the caller
 * believes a filter was applied. Reaching this function it selects nothing,
 * which is the safe half of that pair.
 * Parity: baselineLabelsMatch in go/filter.go.
 */
export function baselineLabelsMatch(
  labels: Record<string, string> | undefined,
  predicates: Values | undefined,
): boolean {
  if (!valuesActive(predicates)) return true;
  return valuesMatch(predicates!, (p) => {
    const colon = p.indexOf(':');
    return colon > 0 && labelMatchesGlob(labels, p.slice(0, colon), p.slice(colon + 1));
  });
}

/**
 * labelMatchesGlob reports whether a label KEY is present and its value matches
 * the pattern. Deliberately not tagMatchesGlob: a tag value may be a list, which
 * is why that one goes through the tag helpers, while a label is exactly one
 * string by schema (`additionalProperties: {type: string}`). An absent key
 * matches nothing, including against `*` — the predicate asks about a label the
 * baseline does not carry, and there is nothing to match.
 * Parity: labelMatchesGlob in go/filter.go.
 */
export function labelMatchesGlob(
  labels: Record<string, string> | undefined,
  key: string,
  pattern: string,
): boolean {
  const value = labels?.[key];
  if (value === undefined) return false;
  return safeGlobMatch(value, pattern);
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
 * The closed vocabulary the poamType filter accepts: the schema's POA&M type
 * enum. Deliberately NOT merged into DISPOSITION_VALUES — disposition answers
 * which Override_Type governs, and a plan's kind is not an override type.
 * Parity: PoamTypeValues in go/filter.go, pinned by the shared case table.
 */
export const POAM_TYPE_VALUES = ['remediation', 'mitigation', 'riskAcceptance', 'vendorDependency'] as const;

/**
 * Reports whether s names a POA&M kind. A value outside the vocabulary can only
 * ever match nothing, so callers refuse it rather than letting it read as
 * "asked and found none".
 * Parity: ValidPoamType in go/filter.go.
 */
export function validPoamType(s: string): boolean {
  return POAM_TYPE_VALUES.some((v) => normalizeKey(v) === normalizeKey(s));
}

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
 * The type of the override that governs the requirement, or '' when none does:
 * the most recently applied non-expired override, whatever it carries. That is
 * the schema's own definition, and the rule hdf-diff has always used to compute
 * the effective checksum.
 *
 * Eligibility is deliberately unfiltered here, unlike the status and impact
 * ladders. Requiring a status — as this did — meant an override carrying only an
 * impact governed nothing, so `--disposition riskAdjustment` could not match the
 * shape a riskAdjustment normally has. The cost is that disposition may name a
 * different override than the one that decided the status, which is what
 * per-field eligibility means rather than a contradiction.
 */
function governingDisposition(control: EvaluatedRequirement, now?: string): string {
  // Overrides and POA&Ms are ONE ordered set, not two tiers: the schema defines
  // disposition as 'the most recent non-expired override or POAM governing this
  // requirement'. Both carry appliedAt and expiresAt with the same meaning, so
  // the existing resolver decides between them without inventing a comparison.
  // Parity: governingDisposition in go/filter.go.
  const overrides = control.statusOverrides ?? [];
  const entries = [...overrideInputs(control), ...poamInputs(control)];

  const index = governingOverrideIndex(entries, () => true, now);
  if (index < 0) return '';
  if (index < overrides.length) return overrides[index]?.type ?? '';
  // A POA&M's own kind — remediation, mitigation, riskAcceptance,
  // vendorDependency — is not a member of Override_Type, which is what
  // disposition is typed as, so every governing POA&M reports the flat 'poam'.
  return 'poam';
}

/**
 * Projects POA&Ms onto the shape the override resolver compares, carrying no
 * status or impact because a POA&M changes neither: it tracks the work being
 * done about a failure rather than adjudicating it.
 * Parity: poamInputs in go/filter.go.
 */
function poamInputs(control: EvaluatedRequirement): StatusOverrideInput[] {
  return (control.poams ?? []).map((p) => ({
    appliedAt: new Date(p.appliedAt).toISOString(),
    expiresAt: new Date(p.expiresAt).toISOString(),
  }));
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
  // A poam-typed statusOverride IS a filed plan, and it is the only form the
  // toolchain actually produces: `hdf amend apply` writes statusOverrides[], no
  // importer emits poams[], and no committed fixture carries one. Reading only
  // poams[] made this predicate dead — "every failure has a current plan" could
  // never pass however many POA&Ms were filed.
  //
  // "Carries" is not the question disposition answers: disposition names the
  // GOVERNING adjudication, so a newer override outranks an older plan without
  // cancelling it and the two can disagree. Parity: go/filter.go hasValidPoam.
  const overridePlan = (control.statusOverrides ?? []).some(
    (o) => o.type === 'poam' && new Date(o.expiresAt).getTime() > ref
  );
  return overridePlan || (control.poams ?? []).some((poam) => new Date(poam.expiresAt).getTime() > ref);
}

/**
 * The requirement's authoritative CVSS score, or undefined when it carries none.
 *
 * Two decisions live here. An entry's score is its computedScore when the
 * producer supplied one, else its baseScore: the schema calls computedScore "the
 * score consumers should treat as authoritative for risk decisions when
 * present", and converters populate it: nessus-to-hdf writes a requirement-level
 * computedScore when it has the metrics to recompute one, and hdf-to-csv already
 * resolves computedScore-else-baseScore for its own column, so a gate reading
 * baseScore alone would disagree with both. It does NOT reach
 * `hdf enrich --recompute-cvss`, which writes its recomputed score into a
 * riskAdjustment OVERRIDE's cvss block rather than the requirement's own cvss[].
 * And a
 * requirement may carry one entry per CVE, resolving to the HIGHEST of them: a
 * finding matching several CVEs is as dangerous as its worst.
 *
 * Parity: cvssScoreOf in go/filter.go.
 */
export function cvssScoreOf(control: EvaluatedRequirement): number | undefined {
  let best: number | undefined;
  for (const entry of control.cvss ?? []) {
    const score = entry.computedScore ?? entry.baseScore;
    if (typeof score === 'number' && (best === undefined || score > best)) best = score;
  }
  return best;
}

/**
 * CISA Known Exploited Vulnerabilities membership. An absent kev block reads as
 * false: a requirement nobody checked against the catalog is not
 * known-exploited, and treating absence as unknown would leave 'kev: false'
 * unable to express "everything CISA does not list".
 */
function inKev(control: EvaluatedRequirement): boolean {
  return control.kev?.inKev === true;
}

/** Accepts only 'true' and 'false'; anything else yields undefined. */
function parseKevFilter(s: string): boolean | undefined {
  switch (s.trim().toLowerCase()) {
    case 'true':
      return true;
    case 'false':
      return false;
    default:
      return undefined;
  }
}

/**
 * Whether a kev filter value is one this engine understands, for callers to
 * reject up front rather than matching nothing.
 */
export function validKevFilter(s: string): boolean {
  return parseKevFilter(s) !== undefined;
}
