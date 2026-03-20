/**
 * HDF v2 native format fingerprint.
 *
 * Detects HDF v2.0 JSON files (the most common upload format). These have
 * a baselines[] array at the top level — no conversion needed, just passthrough.
 *
 * Confidence 0.8: lower than tool-specific formats so that if a file matches
 * a more specific converter (e.g. SARIF, TruffleHog), that wins.
 *
 * No converter imports — data only, safe for client bundles.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const hdfV2Fingerprint: ConverterFingerprint = {
  id: 'hdf-v2-passthrough',
  label: 'HDF v2',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return 0;
    const obj = input as Record<string, unknown>;
    if (Array.isArray(obj.baselines)) return 0.8;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('hdf-v2-passthrough')) return;
  registerFingerprint(hdfV2Fingerprint);
}
