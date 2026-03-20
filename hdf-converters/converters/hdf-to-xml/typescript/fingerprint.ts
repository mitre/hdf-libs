/**
 * HDF-to-XML export fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * direction: 'export' — not a detection target, low confidence (0.5).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const hdfToXmlFingerprint: ConverterFingerprint = {
  id: 'hdf-to-xml',
  label: 'HDF to XML',
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
  if (getFingerprint('hdf-to-xml')) return;
  registerFingerprint(hdfToXmlFingerprint);
}
