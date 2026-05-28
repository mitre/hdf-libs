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
