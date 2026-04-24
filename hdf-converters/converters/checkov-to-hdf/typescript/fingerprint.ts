/**
 * Checkov format fingerprint.
 *
 * Detects JSON with check_type + results.passed_checks/failed_checks (single object or array).
 * Strong signal (1.0) when summary.checkov_version is present; medium (0.8) otherwise.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

function fingerprintObject(obj: Record<string, unknown>): number {
  if (typeof obj.check_type !== 'string') return 0;

  const results = obj.results;
  if (typeof results !== 'object' || results === null) return 0;
  const res = results as Record<string, unknown>;
  if (!Array.isArray(res.passed_checks) && !Array.isArray(res.failed_checks)) return 0;

  // Strong signal: summary with checkov_version
  const summary = obj.summary;
  if (typeof summary === 'object' && summary !== null) {
    const sum = summary as Record<string, unknown>;
    if ('checkov_version' in sum) return 1.0;
  }

  // Medium signal: has check_type + results with check arrays but no version
  return 0.8;
}

export const checkovFingerprint: ConverterFingerprint = {
  id: 'checkov-to-hdf',
  label: 'Checkov',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;

    // Array format: check first element
    if (Array.isArray(input)) {
      if (input.length === 0) return 0;
      const first = input[0] as Record<string, unknown>;
      if (typeof first !== 'object' || first === null) return 0;
      return fingerprintObject(first);
    }

    return fingerprintObject(input as Record<string, unknown>);
  },
};

export function register(): void {
  if (getFingerprint('checkov-to-hdf')) return;
  registerFingerprint(checkovFingerprint);
}
