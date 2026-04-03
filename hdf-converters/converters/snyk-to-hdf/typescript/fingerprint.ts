/**
 * Snyk format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects Snyk JSON by `vulnerabilities[]` array. Returns 1.0 when
 * `packageManager` is also present, 0.5 for just `vulnerabilities[]`.
 * Also handles multi-project array input (array of Snyk reports).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

function isSnykReport(obj: Record<string, unknown>): number {
  if (!Array.isArray(obj.vulnerabilities)) return 0;
  if (typeof obj.packageManager === 'string') return 1.0;
  return 0.5;
}

export const snykFingerprint: ConverterFingerprint = {
  id: 'snyk-to-hdf',
  label: 'Snyk',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    // Handle array input (multi-project)
    if (Array.isArray(input)) {
      if (input.length === 0) return 0;
      const first = input[0] as Record<string, unknown> | undefined;
      if (!first || typeof first !== 'object') return 0;
      return isSnykReport(first);
    }
    // Single project
    return isSnykReport(input as Record<string, unknown>);
  },
};

export function register(): void {
  if (getFingerprint('snyk-to-hdf')) return;
  registerFingerprint(snykFingerprint);
}
