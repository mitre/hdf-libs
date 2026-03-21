/**
 * JFrog Xray format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JFrog Xray JSON by the presence of a `data` array with `total_count`.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const jfrogXrayFingerprint: ConverterFingerprint = {
  id: 'jfrog-xray-to-hdf',
  label: 'JFrog Xray',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (Array.isArray(obj.data) && typeof obj.total_count === 'number') return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('jfrog-xray-to-hdf')) return;
  registerFingerprint(jfrogXrayFingerprint);
}
