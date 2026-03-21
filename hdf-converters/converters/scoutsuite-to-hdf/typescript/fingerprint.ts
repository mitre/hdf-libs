/**
 * ScoutSuite format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects ScoutSuite JSON by the presence of `services` (object) + `last_run` (object).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const scoutsuiteFingerprint: ConverterFingerprint = {
  id: 'scoutsuite-to-hdf',
  label: 'ScoutSuite',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (
      typeof obj.services === 'object' && obj.services !== null && !Array.isArray(obj.services) &&
      typeof obj.last_run === 'object' && obj.last_run !== null
    ) return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('scoutsuite-to-hdf')) return;
  registerFingerprint(scoutsuiteFingerprint);
}
