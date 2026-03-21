/**
 * TruffleHog format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 *
 * TruffleHog output can be:
 * - JSON array of findings
 * - Single JSON object finding
 * - NDJSON (newline-delimited JSON)
 *
 * Key structural markers:
 * - SourceMetadata + DetectorName → confidence 1.0
 * - Raw + Verified (boolean) → confidence 0.7
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

function isTrufflehogFinding(obj: Record<string, unknown>): number {
  if (typeof obj.DetectorName === 'string' && obj.SourceMetadata != null) return 1.0;
  if (typeof obj.Raw === 'string' && typeof obj.Verified === 'boolean') return 0.7;
  return 0;
}

export const trufflehogFingerprint: ConverterFingerprint = {
  id: 'trufflehog-to-hdf',
  label: 'TruffleHog',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;

    // Array of findings
    if (Array.isArray(input)) {
      if (input.length === 0) return 0;
      const first = input[0] as Record<string, unknown>;
      if (typeof first !== 'object' || first === null) return 0;
      return isTrufflehogFinding(first);
    }

    // Single finding object
    return isTrufflehogFinding(input as Record<string, unknown>);
  },
};

export function register(): void {
  if (getFingerprint('trufflehog-to-hdf')) return;
  registerFingerprint(trufflehogFingerprint);
}
