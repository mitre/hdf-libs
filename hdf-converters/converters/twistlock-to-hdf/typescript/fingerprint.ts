/**
 * Twistlock/Prisma Cloud format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 *
 * Twistlock container image scans produce a top-level "results" array where
 * each item has complianceDistribution or vulnerabilityDistribution.
 * Code repository scans omit the results wrapper but still have those fields.
 *
 * Key structural markers:
 * - results[] with complianceDistribution → confidence 1.0
 * - results[] with vulnerabilityDistribution → confidence 0.9
 * - Single object with complianceDistribution → confidence 0.9
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

function hasTwistlockMarkers(obj: Record<string, unknown>): number {
  if ('complianceDistribution' in obj) return 1.0;
  if ('vulnerabilityDistribution' in obj) return 0.9;
  return 0;
}

export const twistlockFingerprint: ConverterFingerprint = {
  id: 'twistlock-to-hdf',
  label: 'Twistlock',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return 0;
    const obj = input as Record<string, unknown>;

    // Container scan with "results" wrapper
    if (Array.isArray(obj.results) && obj.results.length > 0) {
      const first = obj.results[0] as Record<string, unknown>;
      if (typeof first === 'object' && first !== null) {
        return hasTwistlockMarkers(first);
      }
    }

    // Code repo scan — single result object without wrapper
    return hasTwistlockMarkers(obj);
  },
};

export function register(): void {
  if (getFingerprint('twistlock-to-hdf')) return;
  registerFingerprint(twistlockFingerprint);
}
