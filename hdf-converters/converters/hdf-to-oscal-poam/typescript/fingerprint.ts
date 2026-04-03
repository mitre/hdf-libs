/**
 * HDF-to-OSCAL-POA&M export fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * direction: 'export' — not a detection target, low confidence (0.5).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const hdfToOscalPoamFingerprint: ConverterFingerprint = {
  id: 'hdf-to-oscal-poam',
  label: 'HDF to OSCAL POA&M',
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
  if (getFingerprint('hdf-to-oscal-poam')) return;
  registerFingerprint(hdfToOscalPoamFingerprint);
}
