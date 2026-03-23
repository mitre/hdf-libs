/**
 * CycloneDX format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JSON with bomFormat === 'CycloneDX'.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const cyclonedxFingerprint: ConverterFingerprint = {
  id: 'cyclonedx-to-hdf',
  label: 'CycloneDX',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (obj.bomFormat === 'CycloneDX') return 1.0;
    return 0;
  },
  detectVersion: (input: unknown): string => {
    if (typeof input !== 'object' || input === null) return '';
    const obj = input as Record<string, unknown>;
    return typeof obj.specVersion === 'string' ? obj.specVersion : '';
  },
};

export function register(): void {
  if (getFingerprint('cyclonedx-to-hdf')) return;
  registerFingerprint(cyclonedxFingerprint);
}
