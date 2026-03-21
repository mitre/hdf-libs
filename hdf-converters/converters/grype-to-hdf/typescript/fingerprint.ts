/**
 * Grype format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JSON with matches[] + source (1.0) or descriptor.name === 'grype' (0.8).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const grypeFingerprint: ConverterFingerprint = {
  id: 'grype-to-hdf',
  label: 'Grype',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    // Strong signal: matches array with source object (standard Grype output)
    if (Array.isArray(obj.matches) && typeof obj.source === 'object' && obj.source !== null) return 1.0;
    // Medium signal: descriptor.name === 'grype'
    if (typeof obj.descriptor === 'object' && obj.descriptor !== null) {
      const desc = obj.descriptor as Record<string, unknown>;
      if (desc.name === 'grype') return 0.8;
    }
    // Weak signal: matches array alone (could be other tools)
    if (Array.isArray(obj.matches)) return 0.4;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('grype-to-hdf')) return;
  registerFingerprint(grypeFingerprint);
}
