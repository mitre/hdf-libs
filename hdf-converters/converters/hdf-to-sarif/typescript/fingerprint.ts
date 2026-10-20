/**
 * HDF-to-SARIF export fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * direction: 'export' — not a detection target, low confidence (0.5).
 */

import {
  type ConverterFingerprint,
  getFingerprint,
  registerFingerprint,
} from '../../../shared/typescript/registry.js';

export const hdfToSarifFingerprint: ConverterFingerprint = {
  id: 'hdf-to-sarif',
  label: 'HDF to SARIF',
  direction: 'export',
  inputFamily: 'json',
  outputType: 'raw',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (Array.isArray(obj.baselines)) return 0.5;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('hdf-to-sarif')) return;
  registerFingerprint(hdfToSarifFingerprint);
}
