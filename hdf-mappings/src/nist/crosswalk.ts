/**
 * NIST SP 800-53 Rev 4 <-> Rev 5 control crosswalk, generated from NIST's own
 * comparison workbooks (see scripts/generate-nist-crosswalk.mjs). Identity is
 * implicit: a control present in both revisions translates to itself; edges
 * cover only non-identity cases (withdrawn, moved, incorporated, Appendix J
 * pointers, and controls new in Rev 5).
 */

import rawCrosswalk from '../data/nist-revision-crosswalk.json';

/**
 * Relations a translation can carry. `identity` means the control exists at
 * both revisions under the same ID; `moved`/`incorporated`/`pointer`/`family`
 * come from NIST's comparison workbooks; `none` means NIST names no successor;
 * `unknown` means the control is not part of the source revision's catalog (or
 * the revision pair is unsupported).
 */
export type NistCrosswalkRelation =
  | 'identity'
  | 'moved'
  | 'incorporated'
  | 'pointer'
  | 'family'
  | 'none'
  | 'unknown';

export interface NistControlTranslation {
  control: string;
  targets: string[];
  relation: NistCrosswalkRelation;
  /**
   * Set only for relation `family` ("incorporated into <XX> family"): a
   * marker, deliberately never expanded into member controls.
   */
  family?: string;
  /** NIST's raw comparison text for redirects. */
  detail?: string;
}

interface CrosswalkEdge {
  from: number;
  control: string;
  targets: string[];
  relation: string;
  family?: string;
  detail: string;
}

interface CrosswalkFile {
  rosters: Record<string, string[]>;
  edges: CrosswalkEdge[];
}

const crosswalk = rawCrosswalk as unknown as CrosswalkFile;

const rosters = new Map<number, Set<string>>(
  Object.entries(crosswalk.rosters).map(([rev, ids]) => [Number(rev), new Set(ids)])
);

const edges = new Map<number, Map<string, CrosswalkEdge>>();
for (const edge of crosswalk.edges) {
  let byControl = edges.get(edge.from);
  if (!byControl) {
    byControl = new Map();
    edges.set(edge.from, byControl);
  }
  byControl.set(edge.control, edge);
}

const SUPPORTED = new Set([4, 5]);
/** A trailing single-letter statement part, e.g. "AC-2(j)". */
const STATEMENT_LETTER = /^(.*)\(([a-z])\)$/;

function fromEdge(control: string, edge: CrosswalkEdge): NistControlTranslation {
  const tr: NistControlTranslation = {
    control,
    targets: [...edge.targets],
    relation: edge.relation as NistCrosswalkRelation,
    detail: edge.detail,
  };
  if (edge.family) tr.family = edge.family;
  return tr;
}

function identity(control: string): NistControlTranslation {
  return { control, targets: [control], relation: 'identity' };
}

/**
 * Translates one NIST control ID between 800-53 revisions 4 and 5. A control
 * present in both revisions translates to itself (identity); withdrawn, moved,
 * incorporated, and Appendix J controls follow NIST's published successors; a
 * control with no equivalent at the target revision gets relation `none` and
 * no targets. Statement-letter suffixes ("AC-2(j)") survive identity
 * translation and are dropped on redirects.
 */
export function translateNistControl(
  control: string,
  from: number,
  to: number
): NistControlTranslation {
  if (!control || !SUPPORTED.has(from) || !SUPPORTED.has(to)) {
    return { control, targets: [], relation: 'unknown' };
  }
  if (from === to) return identity(control);

  const edge = edges.get(from)?.get(control);
  if (edge) return fromEdge(control, edge);
  if (rosters.get(from)?.has(control) && rosters.get(to)?.has(control)) {
    return identity(control);
  }

  const base = STATEMENT_LETTER.exec(control)?.[1];
  if (base) {
    const baseEdge = edges.get(from)?.get(base);
    if (baseEdge) return fromEdge(control, baseEdge);
    if (rosters.get(from)?.has(base) && rosters.get(to)?.has(base)) {
      return identity(control);
    }
  }
  return { control, targets: [], relation: 'unknown' };
}

/**
 * Translates a list of control IDs between revisions, flattening redirect
 * targets and deduplicating while preserving first-seen order. Controls with
 * no target at the destination revision (withdrawn without successor,
 * family-level, or unknown) are returned in `unmapped`, in input order, so
 * callers can surface them instead of silently dropping.
 */
export function translateNistControls(
  controls: string[],
  from: number,
  to: number
): { translated: string[]; unmapped: NistControlTranslation[] } {
  const translated: string[] = [];
  const unmapped: NistControlTranslation[] = [];
  const seen = new Set<string>();
  for (const control of controls) {
    const tr = translateNistControl(control, from, to);
    if (tr.targets.length === 0) {
      unmapped.push(tr);
      continue;
    }
    for (const target of tr.targets) {
      if (!seen.has(target)) {
        seen.add(target);
        translated.push(target);
      }
    }
  }
  return { translated, unmapped };
}

/**
 * Number of control IDs in the crosswalk's catalog for the given revision, or
 * 0 for unsupported revisions.
 */
export function nistRosterSize(rev: number): number {
  return rosters.get(rev)?.size ?? 0;
}

/**
 * A NIST-shaped base at the start of a longer reference, e.g. "AC-1 a",
 * "AC-1.2 (i)", "SA-12 b 1" — DISA-CCI statement-reference styles.
 */
const BASE_CONTROL = /^([A-Z]{2}-\d+(?:\(\d+\))?)/;

/**
 * Translates a control list authored against `nativeRev` into `rev`. Identity
 * when the revisions are equal (or either is unsupported). Per token: the
 * crosswalk redirect is followed when one exists; statement-style suffixes
 * ("AC-1 a", "AC-1.2 (i)") are kept on identity and dropped on redirects;
 * tokens with no equivalent at the target revision are dropped (the analog of
 * the awsconfig empty-NIST-ID marker); tokens outside both NIST catalogs
 * (tool placeholders like "UM-1") pass through unchanged — they are not ours
 * to drop. Output is deduplicated preserving first-seen order.
 */
export function nistControlsAtRevision(
  controls: string[],
  nativeRev: number,
  rev: number
): string[] {
  if (nativeRev === rev || !SUPPORTED.has(nativeRev) || !SUPPORTED.has(rev)) {
    return controls;
  }
  const seen = new Set<string>();
  const out: string[] = [];
  const add = (c: string): void => {
    if (c && !seen.has(c)) {
      seen.add(c);
      out.push(c);
    }
  };
  for (const c of controls) {
    const tr = translateNistControl(c, nativeRev, rev);
    if (tr.relation !== 'unknown') {
      tr.targets.forEach(add);
      continue;
    }
    const base = BASE_CONTROL.exec(c)?.[1];
    if (base && base !== c) {
      const btr = translateNistControl(base, nativeRev, rev);
      if (btr.relation === 'identity') {
        add(c);
        continue;
      }
      if (btr.relation !== 'unknown') {
        btr.targets.forEach(add);
        continue;
      }
    }
    add(c);
  }
  return out;
}
