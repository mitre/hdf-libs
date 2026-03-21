/**
 * HDF-to-CSV export fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * direction: 'export' — not a detection target, low confidence (0.5).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const hdfToCsvFingerprint: ConverterFingerprint = {
  id: 'hdf-to-csv',
  label: 'HDF to CSV',
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
  if (getFingerprint('hdf-to-csv')) return;
  registerFingerprint(hdfToCsvFingerprint);
}
