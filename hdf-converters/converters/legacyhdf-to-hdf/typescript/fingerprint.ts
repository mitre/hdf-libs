/**
 * HDF v1 (legacy) format fingerprint.
 *
 * Detects HDF v1.0 JSON files that need conversion to v2.0 format.
 * V1 files have a profiles[] array at root, a platform object, and a
 * version string. They do NOT have baselines[] (that is v2).
 *
 * The isLegacyHdf() function in the converter checks:
 *   typeof obj.version === 'string' && Array.isArray(obj.profiles) &&
 *   typeof obj.platform === 'object' && obj.platform !== null
 *
 * No converter imports — data only, safe for client bundles.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const legacyHdfFingerprint: ConverterFingerprint = {
  id: 'legacyhdf-to-hdf',
  label: 'HDF v1 (Legacy)',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return 0;
    const obj = input as Record<string, unknown>;

    // Must NOT have baselines[] (that would be HDF v2)
    if (Array.isArray(obj.baselines)) return 0;

    // V1 structure: profiles[] + platform object + version string
    if (
      typeof obj.version === 'string' &&
      Array.isArray(obj.profiles) &&
      typeof obj.platform === 'object' &&
      obj.platform !== null
    ) {
      return 1.0;
    }

    return 0;
  },
  detectVersion: (input: unknown): string => {
    if (typeof input !== 'object' || input === null) return '';
    const obj = input as Record<string, unknown>;
    return typeof obj.version === 'string' ? obj.version : '';
  },
};

export function register(): void {
  if (getFingerprint('legacyhdf-to-hdf')) return;
  registerFingerprint(legacyHdfFingerprint);
}
