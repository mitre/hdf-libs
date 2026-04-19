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
 * @param severity - Severity level (case-insensitive)
 * @returns Impact score between 0.0 and 1.0; defaults to 0.5 for unrecognized values
 */
export function severityToImpact(severity: string): number {
  const normalized = severity.toLowerCase();
  return severityMap[normalized] ?? 0.5;
}

/**
 * Map an impact score to a severity string.
 *
 * @param impact - Impact score (0.0 to 1.0)
 * @returns Severity level string
 */
export function impactToSeverity(impact: number): string {
  if (impact >= 0.9) return 'critical';
  if (impact >= 0.7) return 'high';
  if (impact >= 0.4) return 'medium';
  if (impact > 0.0) return 'low';
  return 'informational';
}
