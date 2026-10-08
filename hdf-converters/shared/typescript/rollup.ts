/**
 * Requirement roll-up — the single implementation of ADR-0017 §6 ("Requirement
 * roll-up: one requirement per id, within one baseline"). Keep in lockstep with
 * shared/go/rollup.go; the two are compared case for case through
 * hdf-converters/shared/rollup-cases.json.
 *
 * The parameter is ONE baseline's requirement slice, never a document: a
 * document-wide merge would collapse findings from different hosts that share an
 * id (prisma's golden carries 16 baselines, 94 entries, 53 distinct ids but 92
 * distinct (baseline, id) pairs), so the wrong call is deliberately not
 * expressible.
 *
 * ADR-0017 §6, field by field — the table below is the ADR's, in its order, and
 * hdf-converters/shared/rollup-field-rules.json pins it so neither language can
 * drift from it or from the ADR:
 *
 *   id                                             the merge key
 *   results                                        concatenate, source order
 *   affectedPackages                               union, de-duplicated on purl else name+version
 *   code                                           first-wins
 *   cwe refs externalReferences evidence
 *     statusOverrides poams                        union, de-duplicated on identity
 *   tags                                           per key: array-valued union, scalar first-wins
 *   impact severity effectiveImpact                worst-wins
 *   title descriptions                             first-wins
 *   sourceLocation                                 first-wins
 *   controlType verificationMethod applicability   first-wins
 *   cvss epss kev                                  first-wins
 *   effectiveStatus disposition effectiveChecksum  not merged — derived after merging
 */
import type { AffectedPackage, EvaluatedRequirement, Severity } from '@mitre/hdf-schema';
import { UNRATED_SEVERITY_TAG, UNRATED_SEVERITY_VALUE } from './unrated.js';

/**
 * Merge the entries of one baseline's requirement slice that share an id, per
 * ADR-0017 §6. The surviving requirement sits at the position of its first
 * member and its results are in first-seen order; an array with no repeated id
 * is returned unchanged. Inputs are never mutated.
 *
 * An entry whose id is empty is passed through untouched and is never a merge
 * key: id is schema-required, so an empty one is malformed input, and merging on
 * it would fuse unrelated findings.
 */
export function rollUpRequirements(reqs: EvaluatedRequirement[]): EvaluatedRequirement[] {
  const out: EvaluatedRequirement[] = [];
  const at = new Map<string, number>();
  for (const r of reqs) {
    if (!r.id) {
      out.push(r);
      continue;
    }
    const i = at.get(r.id);
    // `held` is read out before the branch because noUncheckedIndexedAccess types
    // an indexed read as possibly-undefined; the index came from `at`, so it never is.
    const held = i === undefined ? undefined : out[i];
    if (i !== undefined && held !== undefined) {
      out[i] = mergeRequirement(held, r);
      continue;
    }
    at.set(r.id, out.length);
    out.push(r);
  }
  return out;
}

/**
 * Fold src into dst, which already holds the group's first member. Every
 * assignment below is one row of the ADR-0017 §6 table, in its order. Returns a
 * new object: the caller's requirements are left untouched.
 */
function mergeRequirement(
  dst: EvaluatedRequirement,
  src: EvaluatedRequirement,
): EvaluatedRequirement {
  const merged: EvaluatedRequirement = { ...dst };

  // results: concatenate, in source order.
  merged.results = [...dst.results, ...src.results];

  // affectedPackages: union, de-duplicated on purl where present, else name + version.
  merged.affectedPackages = unionBy(dst.affectedPackages, src.affectedPackages, packageIdentity);

  // code: first-wins.

  // cwe, refs, externalReferences, evidence, statusOverrides, poams: union,
  // de-duplicated on identity where the member has one. Only cwe declares an
  // identity (the string itself); for the rest the member's whole value is its
  // identity, which is the only key that cannot discard a distinct member.
  merged.cwe = unionBy(dst.cwe, src.cwe, (s) => s);
  merged.refs = unionBy(dst.refs, src.refs, canonical);
  merged.externalReferences = unionBy(dst.externalReferences, src.externalReferences, canonical);
  merged.evidence = unionBy(dst.evidence, src.evidence, canonical);
  merged.statusOverrides = unionBy(dst.statusOverrides, src.statusOverrides, canonical);
  merged.poams = unionBy(dst.poams, src.poams, canonical);

  // tags: per key — array-valued tags union, scalar-valued tags first-wins, a
  // key only a later member carries is added. The unrated-severity marker is
  // the one exception and is handled below.
  const dstUnrated = isUnratedMarked(dst.tags);
  merged.tags = mergeTags(dst.tags, src.tags);

  // The unrated-severity marker is DERIVED, not a scalar tag. It asserts that
  // the severity was defaulted rather than rated, which holds of the merged
  // requirement only if it held of every member — so it survives as an AND and
  // any member lacking it drops it. Merged as an ordinary tag it would be wrong
  // both ways: added from a later member it labels a rated requirement unrated,
  // and kept from the first member it claims no rating beside a genuine
  // worst-wins severity. Unlike the derived fields below, the caller cannot
  // recompute it: once merged, nothing distinguishes a rated severity from a
  // defaulted one.
  if (!(dstUnrated && isUnratedMarked(src.tags))) {
    merged.tags = withoutUnratedMarker(merged.tags);
  }

  // impact, severity, effectiveImpact: worst-wins.
  merged.impact = Math.max(dst.impact, src.impact);
  merged.severity = worstSeverity(dst.severity, src.severity);
  merged.effectiveImpact = worstImpact(dst.effectiveImpact, src.effectiveImpact);

  // title, descriptions: first-wins.
  // sourceLocation: first-wins.
  // controlType, verificationMethod, applicability: first-wins.
  // cvss, epss, kev: first-wins.

  // effectiveStatus, disposition, effectiveChecksum: not merged — derived after
  // merging, from the merged results and overrides. The first member's values
  // describe only that member, so they are dropped rather than carried.
  delete merged.effectiveStatus;
  delete merged.disposition;
  delete merged.effectiveChecksum;

  dropUndefined(merged);
  return merged;
}

/**
 * Append the members of b whose key is not already present in a, preserving
 * source order. An absent field stays absent.
 *
 * `a` is returned unfiltered, so de-duplication is deliberately ASYMMETRIC: the
 * merge never adds a duplicate, but a member's own repeated values survive. That
 * is the point — re-writing the field into a set would silently drop a duplicate
 * the converter chose to emit, which is the loss ADR-0017 §6's whole-member
 * identity exists to avoid. Repeated values do occur in committed output
 * (sarif-to-hdf goldens carry requirements with repeated statusOverrides).
 */
function unionBy<T>(
  a: T[] | undefined,
  b: T[] | undefined,
  key: (v: T) => string,
): T[] | undefined {
  if (b === undefined || b.length === 0) return a;
  const seen = new Set<string>((a ?? []).map(key));
  const add: T[] = [];
  for (const v of b) {
    const k = key(v);
    if (seen.has(k)) continue;
    seen.add(k);
    add.push(v);
  }
  if (add.length === 0) return a;
  return [...(a ?? []), ...add];
}

/**
 * The shared unrated-severity marker. Declared here rather than imported from
 * converterutil.ts, which re-exports rollUpRequirements from this module and
 * would form an import cycle. rollup.test.ts asserts the two agree.
 */

/** Whether a tag map carries the shared unrated-severity marker. */
function isUnratedMarked(tags: EvaluatedRequirement['tags']): boolean {
  return (tags as Record<string, unknown> | undefined)?.[UNRATED_SEVERITY_TAG] === UNRATED_SEVERITY_VALUE;
}

/**
 * Returns tags without the unrated-severity marker, allocating only when the
 * marker is present. Never mutates its argument: mergeTags hands back the
 * caller's own object when the later member has no tags, so deleting in place
 * would reach into the input requirement.
 */
function withoutUnratedMarker(tags: EvaluatedRequirement['tags']): EvaluatedRequirement['tags'] {
  // Keyed on the marker's VALUE, not just its name: the key carrying some other
  // value is an ordinary scalar tag and first-wins per ADR-0017 §6.
  const bag = tags as Record<string, unknown> | undefined;
  if (bag === undefined || !isUnratedMarked(tags)) return tags;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(bag)) {
    if (k !== UNRATED_SEVERITY_TAG) out[k] = v;
  }
  return out as EvaluatedRequirement['tags'];
}

/**
 * ADR-0017 §6's de-duplication key for affectedPackages: the purl where present,
 * else name + version. Joined on NUL, which no name or version contains, so a
 * name holding the separator cannot forge another package's key.
 */
function packageIdentity(p: AffectedPackage): string {
  if (p.purl) return `purl\u0000${p.purl}`;
  return `nv\u0000${p.name ?? ''}\u0000${p.version ?? ''}`;
}

/**
 * The identity of a member that declares none of its own: its whole value, with
 * object keys sorted so two structurally equal members key the same however they
 * were built — the JSON.stringify key order would otherwise depend on
 * construction order, where Go's marshaller is deterministic.
 */
function canonical(v: unknown): string {
  return JSON.stringify(sortKeys(v));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v === null || typeof v !== 'object') return v;
  const entries = Object.entries(v as Record<string, unknown>)
    .filter(([, value]) => value !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return Object.fromEntries(entries.map(([k, value]) => [k, sortKeys(value)]));
}

/**
 * ADR-0017 §6's per-key tag rule: a key both sides carry as an array unions
 * (de-duplicated, source order); every other key first-wins. A key only the later
 * member carries is added — the rule is stated per key, not over the first
 * member's key set.
 */
function mergeTags(
  dst: EvaluatedRequirement['tags'],
  src: EvaluatedRequirement['tags'],
): EvaluatedRequirement['tags'] {
  const srcEntries = Object.entries(src ?? {});
  if (srcEntries.length === 0) return dst;
  const out: Record<string, unknown> = { ...dst };
  for (const [k, sv] of srcEntries) {
    if (!(k in out)) {
      out[k] = sv;
      continue;
    }
    const dv = out[k];
    if (Array.isArray(dv) && Array.isArray(sv)) {
      out[k] = unionBy<unknown>(dv, sv, canonical);
    }
    // Otherwise first-wins: out[k] already holds the first member's value.
  }
  return out as EvaluatedRequirement['tags'];
}

/**
 * Orders Severity for worst-wins. A value outside the enum is not a rating at
 * all rather than the lowest rating — hdf-utilities' isUnratedSeverity is
 * explicit that an unrecognized token asserts nothing — so it loses to every
 * rated value, and two of them fall back to first-wins. An unrated SOURCE
 * severity never arrives here as an off-enum value: the converter has already
 * defaulted it (medium, 0.5) and marked it with UNRATED_SEVERITY_TAG.
 */
const SEVERITY_RANK: Record<string, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function severityRank(s: Severity): number {
  return SEVERITY_RANK[s] ?? -1;
}

/** Worst-wins over the present values; absent loses to present, two absent stay absent. */
function worstSeverity(a?: Severity, b?: Severity): Severity | undefined {
  if (b === undefined) return a;
  if (a === undefined) return b;
  return severityRank(b) > severityRank(a) ? b : a;
}

/** Worst-wins over the present values; absent loses to present. */
function worstImpact(a?: number, b?: number): number | undefined {
  if (b === undefined) return a;
  if (a === undefined) return b;
  return b > a ? b : a;
}

/**
 * Drop keys the merge left undefined. Go omits an absent optional field
 * entirely; leaving `key: undefined` on the object would serialize the same but
 * compare differently, and the two languages are compared structurally.
 */
function dropUndefined(r: EvaluatedRequirement): void {
  for (const k of Object.keys(r) as Array<keyof EvaluatedRequirement>) {
    if (r[k] === undefined) delete r[k];
  }
}
