/**
 * Severity-to-impact mapping utilities.
 *
 * These define the canonical bidirectional mapping between severity labels
 * (critical, high, medium, low, informational) and HDF impact scores (0.0–1.0),
 * aligned with CVSS 3.x severity bands normalized to 0–1.
 *
 * Threshold ranges (used by impactToSeverity):
 *   >=0.9       = critical (CVSS 9.0–10.0)
 *   [0.7, 0.9)  = high     (CVSS 7.0–8.9)
 *   [0.4, 0.7)  = medium   (CVSS 4.0–6.9)
 *   (0.0, 0.4)  = low      (CVSS 0.1–3.9)
 *   0.0         = informational (CVSS 0.0)
 */

const severityMap: Record<string, number> = {
  critical: 0.9,
  high: 0.7,
  medium: 0.5,
  low: 0.3,
  info: 0.0,
  none: 0.0,
  informational: 0.0,
  information: 0.0,
};

/**
 * Map a severity string to an impact score.
 *
 * @param severity - Severity level (case-insensitive), or null for no severity assessment
 * @returns Impact score between 0.0 and 1.0; null when input is null; defaults to 0.5 for unrecognized values
 */
export function severityToImpact(severity: null): null;
export function severityToImpact(severity: string): number;
export function severityToImpact(severity: string | null): number | null;
export function severityToImpact(severity: string | null): number | null {
  if (severity === null) return null;
  const normalized = severity.toLowerCase();
  return severityMap[normalized] ?? 0.5;
}

/**
 * Round an HDF impact value to 2 decimal places — its canonical precision —
 * eliminating the representation noise that binary float division leaves behind
 * (e.g. 9.8 / 10 = 0.9800000000000001). Impact is defined on 0.0–1.0 with a
 * natural 0.01 grid (a 1-decimal CVSS score / 10), so this is lossless in
 * intent. Use it wherever impact is COMPUTED (divided or otherwise
 * arithmetically derived), not when assigned from a literal band.
 */
export function roundImpact(x: number): number {
  return Math.round(x * 100) / 100;
}

/**
 * Map an impact score to a severity string.
 *
 * @param impact - Impact score (0.0 to 1.0), or null for no impact assessment
 * @returns Severity level string, or null when input is null
 */
export function impactToSeverity(impact: null): null;
export function impactToSeverity(impact: number): string;
export function impactToSeverity(impact: number | null): string | null;
export function impactToSeverity(impact: number | null): string | null {
  if (impact === null) return null;
  if (impact >= 0.9) return 'critical';
  if (impact >= 0.7) return 'high';
  if (impact >= 0.4) return 'medium';
  if (impact > 0.0) return 'low';
  return 'informational';
}

/**
 * Map a raw CVSS base score (0.0–10.0) to a FIRST qualitative severity band.
 *
 * Bands per FIRST CVSS v3.x / v4.0 spec:
 *   none     = 0.0
 *   low      = 0.1 – 3.9
 *   medium   = 4.0 – 6.9
 *   high     = 7.0 – 8.9
 *   critical = 9.0 – 10.0
 *
 * Out-of-range inputs are clamped: scores < 0.1 → "none" (band floor),
 * scores > 10.0 → "critical". This matches scanner behavior of treating
 * malformed scores as informational/critical extremes rather than throwing.
 *
 * @param score - CVSS base score
 * @returns FIRST severity band label
 */
export function cvssScoreToSeverity(
  score: number,
): 'none' | 'low' | 'medium' | 'high' | 'critical' {
  if (!Number.isFinite(score) || score < 0.1) return 'none';
  if (score < 4.0) return 'low';
  if (score < 7.0) return 'medium';
  if (score < 9.0) return 'high';
  return 'critical';
}

// Severity vocabulary values that assert "no rating was made" (grype Unknown,
// Dependency-Track UNASSIGNED, Microsoft Graph unSpecified). Distinct from the
// zero-impact RATED tier (info/none/informational) and from grype's
// negligible, which is the lowest rating, not an absent one.
const unratedSeverityTokens = new Set(['unknown', 'unassigned', 'unspecified']);

/**
 * Report whether a source severity carries no rating at all: the field is
 * absent/blank, or the token is an explicit no-rating value. Tokens the
 * vocabulary simply doesn't recognize are NOT unrated — an unknown word is not
 * an assertion of unratedness. Converters use this to emit the shared unrated
 * marker so a defaulted impact stays distinguishable from a genuine medium.
 */
export function isUnratedSeverity(severity?: string | null): boolean {
  if (severity === undefined || severity === null) return true;
  const s = severity.trim().toLowerCase();
  return s === '' || unratedSeverityTokens.has(s);
}
