/**
 * SARIF format fingerprint.
 *
 * Exports a ConverterFingerprint object (data only, no converter import).
 * Confidence 0.9 — tool-specific SARIF wrappers (MSDO etc.) return 0.95+.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const sarifFingerprint: ConverterFingerprint = {
  id: 'sarif-to-hdf',
  label: 'SARIF',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (typeof obj.version === 'string' && Array.isArray(obj.runs)) return 0.9;
    return 0;
  },
  detectVersion: (input: unknown): string => {
    if (typeof input !== 'object' || input === null) return '';
    const obj = input as Record<string, unknown>;
    return typeof obj.version === 'string' ? obj.version : '';
  },
};

export function register(): void {
  if (getFingerprint('sarif-to-hdf')) return;
  registerFingerprint(sarifFingerprint);
}
