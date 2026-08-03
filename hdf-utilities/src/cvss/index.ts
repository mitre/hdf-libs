/**
 * CVSS vector parsing and validation utilities.
 *
 * Supports CVSS 2.0 (legacy, no prefix), 3.0, 3.1, and 4.0 vector strings.
 * Parsing is permissive: it splits any well-shaped key:value pair separated
 * by `/`. Validation is strict per the FIRST grammar for each version.
 *
 * References:
 *  - CVSS 2.0:  https://www.first.org/cvss/v2/guide
 *  - CVSS 3.1:  https://www.first.org/cvss/v3.1/specification-document
 *  - CVSS 4.0:  https://www.first.org/cvss/v4.0/specification-document
 */

import cvss40Data from './cvss40-data.json';

export interface ParsedCvssVector {
  /** "2.0" | "3.0" | "3.1" | "4.0" | "unknown" */
  version: string;
  /** Metric name -> metric value (e.g. "AV" -> "N"). Order-preserving via Map. */
  metrics: Map<string, string>;
}

export interface CvssValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Allowed values for each metric, keyed by CVSS major version.
 *
 * Sourced from FIRST specifications (linked above). Only metrics present
 * in a given version's grammar appear in that version's map; unknown metrics
 * encountered during validation are ignored (forward-compat).
 */
const METRIC_VALUES: Record<string, Record<string, string[]>> = {
  '2.0': {
    AV: ['L', 'A', 'N'],
    AC: ['H', 'M', 'L'],
    Au: ['M', 'S', 'N'],
    C: ['N', 'P', 'C'],
    I: ['N', 'P', 'C'],
    A: ['N', 'P', 'C'],
    // Temporal
    E: ['U', 'POC', 'F', 'H', 'ND'],
    RL: ['OF', 'TF', 'W', 'U', 'ND'],
    RC: ['UC', 'UR', 'C', 'ND'],
    // Environmental
    CDP: ['N', 'L', 'LM', 'MH', 'H', 'ND'],
    TD: ['N', 'L', 'M', 'H', 'ND'],
    CR: ['L', 'M', 'H', 'ND'],
    IR: ['L', 'M', 'H', 'ND'],
    AR: ['L', 'M', 'H', 'ND'],
  },
  '3.0': {
    AV: ['N', 'A', 'L', 'P'],
    AC: ['L', 'H'],
    PR: ['N', 'L', 'H'],
    UI: ['N', 'R'],
    S: ['U', 'C'],
    C: ['N', 'L', 'H'],
    I: ['N', 'L', 'H'],
    A: ['N', 'L', 'H'],
    // Temporal
    E: ['X', 'U', 'P', 'F', 'H'],
    RL: ['X', 'O', 'T', 'W', 'U'],
    RC: ['X', 'U', 'R', 'C'],
    // Environmental
    CR: ['X', 'L', 'M', 'H'],
    IR: ['X', 'L', 'M', 'H'],
    AR: ['X', 'L', 'M', 'H'],
    MAV: ['X', 'N', 'A', 'L', 'P'],
    MAC: ['X', 'L', 'H'],
    MPR: ['X', 'N', 'L', 'H'],
    MUI: ['X', 'N', 'R'],
    MS: ['X', 'U', 'C'],
    MC: ['X', 'N', 'L', 'H'],
    MI: ['X', 'N', 'L', 'H'],
    MA: ['X', 'N', 'L', 'H'],
  },
  '3.1': {
    AV: ['N', 'A', 'L', 'P'],
    AC: ['L', 'H'],
    PR: ['N', 'L', 'H'],
    UI: ['N', 'R'],
    S: ['U', 'C'],
    C: ['N', 'L', 'H'],
    I: ['N', 'L', 'H'],
    A: ['N', 'L', 'H'],
    // Temporal
    E: ['X', 'U', 'P', 'F', 'H'],
    RL: ['X', 'O', 'T', 'W', 'U'],
    RC: ['X', 'U', 'R', 'C'],
    // Environmental
    CR: ['X', 'L', 'M', 'H'],
    IR: ['X', 'L', 'M', 'H'],
    AR: ['X', 'L', 'M', 'H'],
    MAV: ['X', 'N', 'A', 'L', 'P'],
    MAC: ['X', 'L', 'H'],
    MPR: ['X', 'N', 'L', 'H'],
    MUI: ['X', 'N', 'R'],
    MS: ['X', 'U', 'C'],
    MC: ['X', 'N', 'L', 'H'],
    MI: ['X', 'N', 'L', 'H'],
    MA: ['X', 'N', 'L', 'H'],
  },
  '4.0': {
    // Base
    AV: ['N', 'A', 'L', 'P'],
    AC: ['L', 'H'],
    AT: ['N', 'P'],
    PR: ['N', 'L', 'H'],
    UI: ['N', 'P', 'A'],
    VC: ['H', 'L', 'N'],
    VI: ['H', 'L', 'N'],
    VA: ['H', 'L', 'N'],
    SC: ['H', 'L', 'N'],
    SI: ['H', 'L', 'N'],
    SA: ['H', 'L', 'N'],
    // Threat
    E: ['X', 'A', 'P', 'U'],
    // Environmental (modified base) — same enums as their base counterparts plus X
    MAV: ['X', 'N', 'A', 'L', 'P'],
    MAC: ['X', 'L', 'H'],
    MAT: ['X', 'N', 'P'],
    MPR: ['X', 'N', 'L', 'H'],
    MUI: ['X', 'N', 'P', 'A'],
    MVC: ['X', 'H', 'L', 'N'],
    MVI: ['X', 'H', 'L', 'N'],
    MVA: ['X', 'H', 'L', 'N'],
    MSC: ['X', 'H', 'L', 'N'],
    MSI: ['X', 'S', 'H', 'L', 'N'],
    MSA: ['X', 'S', 'H', 'L', 'N'],
    // Requirements
    CR: ['X', 'H', 'M', 'L'],
    IR: ['X', 'H', 'M', 'L'],
    AR: ['X', 'H', 'M', 'L'],
    // Supplemental
    S: ['X', 'N', 'P'],
    AU: ['X', 'N', 'Y'],
    R: ['X', 'A', 'U', 'I'],
    V: ['X', 'D', 'C'],
    RE: ['X', 'L', 'M', 'H'],
    U: ['X', 'Clear', 'Green', 'Amber', 'Red'],
  },
};

const REQUIRED_METRICS: Record<string, string[]> = {
  '2.0': ['AV', 'AC', 'Au', 'C', 'I', 'A'],
  '3.0': ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'],
  '3.1': ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'],
  '4.0': ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'],
};

/**
 * Parse a CVSS vector string into version + metric map.
 *
 * Version detection rule: a leading `CVSS:X.Y` segment yields version "X.Y".
 * Otherwise (legacy v2 vectors), version is "2.0". Malformed input yields
 * "unknown" with an empty metric map; no exceptions are thrown.
 *
 * @param vector - CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/...")
 * @returns Parsed version + metric map
 */
export function parseCvssVector(vector: string): ParsedCvssVector {
  const metrics = new Map<string, string>();
  if (typeof vector !== 'string' || vector.length === 0) {
    return { version: 'unknown', metrics };
  }

  const segments = vector.split('/').filter((s) => s.length > 0);
  if (segments.length === 0) {
    return { version: 'unknown', metrics };
  }

  let version = '2.0';
  let start = 0;
  const first = segments[0];
  if (first === undefined) {
    return { version: 'unknown', metrics };
  }
  if (first.startsWith('CVSS:')) {
    version = first.slice(5);
    start = 1;
  } else if (!first.includes(':')) {
    // No prefix AND first segment isn't a key:value pair — bail.
    return { version: 'unknown', metrics };
  }

  for (let i = start; i < segments.length; i++) {
    const seg = segments[i];
    if (seg === undefined) {
      continue;
    }
    const colon = seg.indexOf(':');
    if (colon <= 0 || colon === seg.length - 1) {
      // Skip malformed segments (no colon, empty key, or empty value).
      continue;
    }
    const key = seg.slice(0, colon);
    const value = seg.slice(colon + 1);
    metrics.set(key, value);
  }

  return { version, metrics };
}

/**
 * Validate a CVSS vector string against the FIRST grammar for its version.
 *
 * Checks:
 *  - Version is one of the supported set (2.0, 3.0, 3.1, 4.0).
 *  - All required base metrics for the version are present.
 *  - All known metric values are within the allowed enum.
 *
 * Unknown metric keys are tolerated (forward-compat with future minor versions
 * or scanner-specific extensions). To check a v2 vector without the CVSS:
 * prefix, callers may pass version="2.0" explicitly; otherwise the parser
 * defaults to "2.0" on prefix absence.
 *
 * @param vector  - CVSS vector string
 * @param version - Optional explicit version override (else inferred)
 * @returns `{ valid, errors[] }` — never throws
 */
export function validateCvssVector(
  vector: string,
  version?: string,
): CvssValidationResult {
  const errors: string[] = [];

  if (typeof vector !== 'string' || vector.length === 0) {
    return { valid: false, errors: ['vector is empty'] };
  }

  const parsed = parseCvssVector(vector);
  const v = version ?? parsed.version;

  const grammar = METRIC_VALUES[v];
  const required = REQUIRED_METRICS[v];
  if (!grammar || !required) {
    errors.push(`unsupported CVSS version: ${v}`);
    return { valid: false, errors };
  }

  for (const req of required) {
    if (!parsed.metrics.has(req)) {
      errors.push(`missing required metric: ${req}`);
    }
  }

  for (const [key, value] of parsed.metrics.entries()) {
    const allowed = grammar[key];
    if (!allowed) {
      // Unknown metric: forward-compat — no error.
      continue;
    }
    if (!allowed.includes(value)) {
      errors.push(`invalid value for metric ${key}: ${value} (allowed: ${allowed.join(',')})`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/** A computed CVSS score. */
export interface CvssScore {
  /** CVSS major.minor version the score was computed under (currently always "3.1"). */
  version: string;
  /** Base score (0.0–10.0). */
  baseScore: number;
  /**
   * Temporal (Threat) score (0.0–10.0). Equals baseScore when no temporal
   * metrics (E/RL/RC) are present, per the CVSS 3.1 spec.
   */
  temporalScore: number;
}

// CVSS 3.1 metric weights (FIRST v3.1 specification §7). Privileges Required is
// scope-dependent, hence two tables.
const CVSS31_AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const CVSS31_AC: Record<string, number> = { L: 0.77, H: 0.44 };
const CVSS31_UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CVSS31_CIA: Record<string, number> = { N: 0.0, L: 0.22, H: 0.56 };
const CVSS31_PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const CVSS31_PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const CVSS31_E: Record<string, number> = { X: 1.0, H: 1.0, F: 0.97, P: 0.94, U: 0.91 };
const CVSS31_RL: Record<string, number> = { X: 1.0, U: 1.0, W: 0.97, T: 0.96, O: 0.95 };
const CVSS31_RC: Record<string, number> = { X: 1.0, C: 1.0, R: 0.96, U: 0.92 };

/**
 * CVSS 3.1 Roundup (spec §7.4): the smallest number, to one decimal place, that
 * is >= the input — computed via integer math to avoid the floating-point edge
 * cases 3.0 rounding suffered.
 */
function roundUp31(x: number): number {
  const intInput = Math.round(x * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

function cvss31TemporalWeight(
  table: Record<string, number>,
  metrics: Map<string, string>,
  key: string,
): number {
  const v = metrics.get(key);
  if (v === undefined) {
    return 1.0; // absent → X
  }
  const w = table[v];
  if (w === undefined) {
    throw new Error(`cvss: invalid 3.1 ${key} value "${v}"`);
  }
  return w;
}

/**
 * Compute the CVSS 3.1 Base and Temporal (Threat) scores for a vector string.
 *
 * Only CVSS 3.1 is supported here — CVSS 4.0's MacroVector engine lives
 * separately — so any other version throws rather than returning a wrong number.
 * The peer of the Go `ComputeCvssScore` (kept byte-identical via shared fixtures).
 *
 * @throws if the version is not 3.1, a required base metric is missing, or any
 *   metric value is out of the 3.1 enum.
 */
export function computeCvssScore(vector: string): CvssScore {
  const { version, metrics } = parseCvssVector(vector);
  if (version !== '3.1') {
    throw new Error(`cvss: score compute supports only CVSS 3.1, got "${version}"`);
  }
  for (const k of ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']) {
    if (!metrics.has(k)) {
      throw new Error(`cvss: missing required 3.1 base metric "${k}"`);
    }
  }

  const scope = metrics.get('S');
  if (scope !== 'U' && scope !== 'C') {
    throw new Error(`cvss: invalid 3.1 Scope value "${scope ?? ''}"`);
  }
  const scopeChanged = scope === 'C';

  const prTable = scopeChanged ? CVSS31_PR_CHANGED : CVSS31_PR_UNCHANGED;
  const lookup = (table: Record<string, number>, metric: string): number => {
    const key = metrics.get(metric);
    const w = key === undefined ? undefined : table[key];
    if (w === undefined) {
      throw new Error(`cvss: invalid 3.1 metric value ${metric}:"${key ?? ''}"`);
    }
    return w;
  };
  const av = lookup(CVSS31_AV, 'AV');
  const ac = lookup(CVSS31_AC, 'AC');
  const ui = lookup(CVSS31_UI, 'UI');
  const pr = lookup(prTable, 'PR');
  const c = lookup(CVSS31_CIA, 'C');
  const i = lookup(CVSS31_CIA, 'I');
  const a = lookup(CVSS31_CIA, 'A');

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;

  let baseScore: number;
  if (impact <= 0) {
    baseScore = 0.0;
  } else if (scopeChanged) {
    baseScore = roundUp31(Math.min(1.08 * (impact + exploitability), 10));
  } else {
    baseScore = roundUp31(Math.min(impact + exploitability, 10));
  }

  const e = cvss31TemporalWeight(CVSS31_E, metrics, 'E');
  const rl = cvss31TemporalWeight(CVSS31_RL, metrics, 'RL');
  const rc = cvss31TemporalWeight(CVSS31_RC, metrics, 'RC');
  const temporalScore = roundUp31(baseScore * e * rl * rc);

  return { version: '3.1', baseScore, temporalScore };
}

// --- CVSS 4.0 scoring (MacroVector engine) ---
//
// A faithful port of the FIRST reference calculator (FIRSTdotorg/cvss-v4-calculator:
// cvss_score.js), driven by the MacroVector lookup + max tables extracted verbatim
// into cvss40-data.json. The Go peer (go/cvss.go) reads the byte-identical data
// file and shares the parity fixture, so the two languages score identically.

interface Cvss40Tables {
  lookup: Record<string, number>;
  maxComposed: {
    eq1: Record<string, string[]>;
    eq2: Record<string, string[]>;
    eq3: Record<string, Record<string, string[]>>;
    eq4: Record<string, string[]>;
    eq5: Record<string, string[]>;
  };
  maxSeverity: {
    eq1: Record<string, number>;
    eq2: Record<string, number>;
    eq3eq6: Record<string, Record<string, number>>;
    eq4: Record<string, number>;
    eq5: Record<string, number>;
  };
}
const CVSS40 = cvss40Data as Cvss40Tables;

// Per-metric severity index tables (FIRST reference cvss_score.js). Lower = worse.
const CVSS40_AV: Record<string, number> = { N: 0.0, A: 0.1, L: 0.2, P: 0.3 };
const CVSS40_PR: Record<string, number> = { N: 0.0, L: 0.1, H: 0.2 };
const CVSS40_UI: Record<string, number> = { N: 0.0, P: 0.1, A: 0.2 };
const CVSS40_AC: Record<string, number> = { L: 0.0, H: 0.1 };
const CVSS40_AT: Record<string, number> = { N: 0.0, P: 0.1 };
const CVSS40_VC: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
const CVSS40_SC: Record<string, number> = { H: 0.1, L: 0.2, N: 0.3 };
const CVSS40_SI: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 };
const CVSS40_CR: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };

/** Throw on an unexpected missing table entry rather than fabricate a value. */
function req<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`cvss: 4.0 data table missing ${what}`);
  }
  return value;
}

/**
 * Resolve the effective value of a metric, mirroring the reference m(): E:X and
 * unset default to A (worst case); CR/IR/AR:X and unset default to H; a present,
 * non-X Modified (M-prefixed) metric overrides its base.
 */
function cvss40Metric(sel: Map<string, string>, metric: string): string {
  const selected = sel.get(metric) ?? '';
  if (metric === 'E' && (selected === '' || selected === 'X')) {
    return 'A';
  }
  if ((metric === 'CR' || metric === 'IR' || metric === 'AR') && (selected === '' || selected === 'X')) {
    return 'H';
  }
  const modified = sel.get('M' + metric);
  if (modified !== undefined && modified !== 'X') {
    return modified;
  }
  return selected;
}

function cvss40MacroVectorFromSel(sel: Map<string, string>): string {
  const mv = (k: string): string => cvss40Metric(sel, k);

  // EQ1 (the "not all three N" term of the reference's level-1 clause is
  // redundant here: the level-0 branch already consumes the all-three-N case).
  let eq1 = '2';
  if (mv('AV') === 'N' && mv('PR') === 'N' && mv('UI') === 'N') {
    eq1 = '0';
  } else if ((mv('AV') === 'N' || mv('PR') === 'N' || mv('UI') === 'N') && mv('AV') !== 'P') {
    eq1 = '1';
  }

  let eq2 = '1';
  if (mv('AC') === 'L' && mv('AT') === 'N') {
    eq2 = '0';
  }

  let eq3 = '2';
  if (mv('VC') === 'H' && mv('VI') === 'H') {
    eq3 = '0';
  } else if (mv('VC') === 'H' || mv('VI') === 'H' || mv('VA') === 'H') {
    eq3 = '1';
  }

  let eq4 = '2';
  if (mv('MSI') === 'S' || mv('MSA') === 'S') {
    eq4 = '0';
  } else if (mv('SC') === 'H' || mv('SI') === 'H' || mv('SA') === 'H') {
    eq4 = '1';
  }

  let eq5 = '2';
  if (mv('E') === 'A') {
    eq5 = '0';
  } else if (mv('E') === 'P') {
    eq5 = '1';
  }

  let eq6 = '1';
  if (
    (mv('CR') === 'H' && mv('VC') === 'H') ||
    (mv('IR') === 'H' && mv('VI') === 'H') ||
    (mv('AR') === 'H' && mv('VA') === 'H')
  ) {
    eq6 = '0';
  }

  return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
}

/** Parse a CVSS 4.0 vector and return its MacroVector string. */
export function cvss40MacroVector(vector: string): string {
  return cvss40MacroVectorFromSel(parseCvssVector(vector).metrics);
}

/** Pull a metric's value out of a composed max-vector string (reference extractValueMetric). */
function cvss40ExtractMetric(metric: string, s: string): string {
  const idx = s.indexOf(metric);
  if (idx < 0) {
    return '';
  }
  const rest = s.slice(idx + metric.length + 1);
  const slash = rest.indexOf('/');
  return slash >= 0 ? rest.slice(0, slash) : rest;
}

/** value minus the lower macro's score, or NaN when that lower macro does not exist. */
function cvss40AvailDist(value: number, lowerMacro: string): number {
  const s = CVSS40.lookup[lowerMacro];
  return s === undefined ? NaN : value - s;
}

function cvss40Score(sel: Map<string, string>): number {
  const mv = (k: string): string => cvss40Metric(sel, k);

  if (
    mv('VC') === 'N' && mv('VI') === 'N' && mv('VA') === 'N' &&
    mv('SC') === 'N' && mv('SI') === 'N' && mv('SA') === 'N'
  ) {
    return 0.0;
  }

  const macro = cvss40MacroVectorFromSel(sel);
  let value = req(CVSS40.lookup[macro], `lookup[${macro}]`);

  // Definite per-position digit chars (charAt never yields undefined).
  const c0 = macro.charAt(0);
  const c1 = macro.charAt(1);
  const c2 = macro.charAt(2);
  const c3 = macro.charAt(3);
  const c4 = macro.charAt(4);
  const c5 = macro.charAt(5);

  const d = (i: number): number => macro.charCodeAt(i) - 48;
  const eq3 = d(2);
  const eq6 = d(5);
  const rep = (i: number, digit: number): string =>
    macro.slice(0, i) + String(digit) + macro.slice(i + 1);

  const availDistEq1 = cvss40AvailDist(value, rep(0, d(0) + 1));
  const availDistEq2 = cvss40AvailDist(value, rep(1, d(1) + 1));
  const availDistEq4 = cvss40AvailDist(value, rep(3, d(3) + 1));
  const availDistEq5 = cvss40AvailDist(value, rep(4, d(4) + 1));

  // eq3 and eq6 are coupled.
  let availDistEq3eq6 = NaN;
  if ((eq3 === 1 && eq6 === 1) || (eq3 === 0 && eq6 === 1)) {
    availDistEq3eq6 = cvss40AvailDist(value, rep(2, eq3 + 1));
  } else if (eq3 === 1 && eq6 === 0) {
    availDistEq3eq6 = cvss40AvailDist(value, rep(5, eq6 + 1));
  } else if (eq3 === 0 && eq6 === 0) {
    const left = CVSS40.lookup[rep(5, eq6 + 1)];
    const right = CVSS40.lookup[rep(2, eq3 + 1)];
    if (left !== undefined && right !== undefined) {
      availDistEq3eq6 = value - Math.max(left, right);
    } else if (right !== undefined) {
      availDistEq3eq6 = value - right;
    }
  } else {
    availDistEq3eq6 = cvss40AvailDist(value, macro.slice(0, 2) + String(eq3 + 1) + macro.slice(3, 5) + String(eq6 + 1));
  }

  const eq1Maxes = req(CVSS40.maxComposed.eq1[c0], `maxComposed.eq1[${c0}]`);
  const eq2Maxes = req(CVSS40.maxComposed.eq2[c1], `maxComposed.eq2[${c1}]`);
  const eq3eq6Maxes = req(
    req(CVSS40.maxComposed.eq3[c2], `maxComposed.eq3[${c2}]`)[c5],
    `maxComposed.eq3[${c2}][${c5}]`,
  );
  const eq4Maxes = req(CVSS40.maxComposed.eq4[c3], `maxComposed.eq4[${c3}]`);
  const eq5Maxes = req(CVSS40.maxComposed.eq5[c4], `maxComposed.eq5[${c4}]`);

  const maxVectors: string[] = [];
  for (const a of eq1Maxes) {
    for (const b of eq2Maxes) {
      for (const c of eq3eq6Maxes) {
        for (const e of eq4Maxes) {
          for (const f of eq5Maxes) {
            maxVectors.push(a + b + c + e + f);
          }
        }
      }
    }
  }

  const dist = (table: Record<string, number>, metric: string, maxVector: string): number =>
    req(table[mv(metric)], `level ${metric}:${mv(metric)}`) -
    req(table[cvss40ExtractMetric(metric, maxVector)], `max level ${metric}`);

  let sdAV = 0, sdPR = 0, sdUI = 0, sdAC = 0, sdAT = 0, sdVC = 0, sdVI = 0, sdVA = 0;
  let sdSC = 0, sdSI = 0, sdSA = 0, sdCR = 0, sdIR = 0, sdAR = 0;
  for (const maxVector of maxVectors) {
    sdAV = dist(CVSS40_AV, 'AV', maxVector);
    sdPR = dist(CVSS40_PR, 'PR', maxVector);
    sdUI = dist(CVSS40_UI, 'UI', maxVector);
    sdAC = dist(CVSS40_AC, 'AC', maxVector);
    sdAT = dist(CVSS40_AT, 'AT', maxVector);
    sdVC = dist(CVSS40_VC, 'VC', maxVector);
    sdVI = dist(CVSS40_VC, 'VI', maxVector);
    sdVA = dist(CVSS40_VC, 'VA', maxVector);
    sdSC = dist(CVSS40_SC, 'SC', maxVector);
    sdSI = dist(CVSS40_SI, 'SI', maxVector);
    sdSA = dist(CVSS40_SI, 'SA', maxVector);
    sdCR = dist(CVSS40_CR, 'CR', maxVector);
    sdIR = dist(CVSS40_CR, 'IR', maxVector);
    sdAR = dist(CVSS40_CR, 'AR', maxVector);
    if (
      [sdAV, sdPR, sdUI, sdAC, sdAT, sdVC, sdVI, sdVA, sdSC, sdSI, sdSA, sdCR, sdIR, sdAR].some(
        (v) => v < 0,
      )
    ) {
      continue;
    }
    break;
  }

  const curEq1 = sdAV + sdPR + sdUI;
  const curEq2 = sdAC + sdAT;
  const curEq3eq6 = sdVC + sdVI + sdVA + sdCR + sdIR + sdAR;
  const curEq4 = sdSC + sdSI + sdSA;

  const step = 0.1;
  const maxSevEq1 = req(CVSS40.maxSeverity.eq1[c0], `maxSeverity.eq1[${c0}]`) * step;
  const maxSevEq2 = req(CVSS40.maxSeverity.eq2[c1], `maxSeverity.eq2[${c1}]`) * step;
  const maxSevEq3eq6 =
    req(
      req(CVSS40.maxSeverity.eq3eq6[c2], `maxSeverity.eq3eq6[${c2}]`)[c5],
      `maxSeverity.eq3eq6[${c2}][${c5}]`,
    ) * step;
  const maxSevEq4 = req(CVSS40.maxSeverity.eq4[c3], `maxSeverity.eq4[${c3}]`) * step;

  let nExisting = 0;
  let normEq1 = 0, normEq2 = 0, normEq3eq6 = 0, normEq4 = 0;
  const normEq5 = 0; // eq5 proportion is always 0 per the reference
  if (!Number.isNaN(availDistEq1)) {
    nExisting++;
    normEq1 = availDistEq1 * (curEq1 / maxSevEq1);
  }
  if (!Number.isNaN(availDistEq2)) {
    nExisting++;
    normEq2 = availDistEq2 * (curEq2 / maxSevEq2);
  }
  if (!Number.isNaN(availDistEq3eq6)) {
    nExisting++;
    normEq3eq6 = availDistEq3eq6 * (curEq3eq6 / maxSevEq3eq6);
  }
  if (!Number.isNaN(availDistEq4)) {
    nExisting++;
    normEq4 = availDistEq4 * (curEq4 / maxSevEq4);
  }
  if (!Number.isNaN(availDistEq5)) {
    nExisting++;
  }

  const meanDistance =
    nExisting === 0 ? 0 : (normEq1 + normEq2 + normEq3eq6 + normEq4 + normEq5) / nExisting;

  value -= meanDistance;
  if (value < 0) {
    value = 0.0;
  }
  if (value > 10) {
    value = 10.0;
  }
  return Math.round(value * 10) / 10;
}

/** Remove the E: segment so the Base score reflects the worst-case default (E:X → E:A). */
function cvss40StripExploitMaturity(vector: string): string {
  return vector
    .split('/')
    .filter((seg) => !seg.startsWith('E:'))
    .join('/');
}

/**
 * Compute the CVSS 4.0 score for a vector string, split into a Base score
 * (`baseScore`, with Exploit Maturity stripped to its worst-case default E:A) and
 * a Threat score (`temporalScore`, with the E value present in the vector). For a
 * base-only vector the two are equal. The peer of the Go `ComputeCvss40Score`,
 * kept byte-identical via the shared data file and parity fixture.
 *
 * @throws if the version is not 4.0, a required base metric is missing, or any
 *   metric value is out of the 4.0 enum.
 */
export function computeCvss40Score(vector: string): CvssScore {
  const { version } = parseCvssVector(vector);
  if (version !== '4.0') {
    throw new Error(`cvss: 4.0 score compute supports only CVSS 4.0, got "${version}"`);
  }
  const { valid, errors } = validateCvssVector(vector, '4.0');
  if (!valid) {
    throw new Error(`cvss: invalid 4.0 vector: ${errors.join('; ')}`);
  }

  const temporalScore = cvss40Score(parseCvssVector(vector).metrics);
  const baseScore = cvss40Score(parseCvssVector(cvss40StripExploitMaturity(vector)).metrics);
  return { version: '4.0', baseScore, temporalScore };
}
