/**
 * Native HDF format fingerprint.
 *
 * Detects HDF JSON files (the most common upload format). These have a
 * baselines[] array at the top level — no conversion needed, just passthrough.
 *
 * Confidence 0.8: lower than tool-specific formats so that if a file matches
 * a more specific converter (e.g. SARIF, TruffleHog), that wins.
 *
 * No converter imports — data only, safe for client bundles.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

/** Detection ID for native (already-HDF) input. */
export const HDF_PASSTHROUGH_ID = 'hdf-passthrough';

export const hdfFingerprint: ConverterFingerprint = {
  id: HDF_PASSTHROUGH_ID,
  label: 'HDF',
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
  if (getFingerprint(HDF_PASSTHROUGH_ID)) return;
  registerFingerprint(hdfFingerprint);
}
