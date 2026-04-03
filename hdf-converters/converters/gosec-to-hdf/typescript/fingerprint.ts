/**
 * GoSec format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Detects JSON with GosecVersion + Issues[] (1.0) or Issues[] + Stats (0.6).
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const gosecFingerprint: ConverterFingerprint = {
  id: 'gosec-to-hdf',
  label: 'GoSec',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    // Strong signal: GosecVersion present with Issues array
    if (typeof obj.GosecVersion === 'string' && Array.isArray(obj.Issues)) return 1.0;
    // Medium signal: Issues array with Stats object (gosec shape without version)
    if (Array.isArray(obj.Issues) && typeof obj.Stats === 'object' && obj.Stats !== null) return 0.6;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('gosec-to-hdf')) return;
  registerFingerprint(gosecFingerprint);
}
