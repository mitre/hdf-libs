/**
 * Nikto format fingerprint.
 *
 * Detects Nikto JSON output by checking for a vulnerabilities array.
 * Nikto outputs JSON (not XML), containing host/port/vulnerabilities fields.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const niktoFingerprint: ConverterFingerprint = {
  id: 'nikto-to-hdf',
  label: 'Nikto',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    // Nikto JSON has a "vulnerabilities" array and optionally "host", "port", "banner"
    if (Array.isArray(obj.vulnerabilities)) {
      // Higher confidence if host/port present (standard Nikto fields)
      if (typeof obj.host === 'string' || typeof obj.port === 'string') return 0.95;
      return 0.85;
    }
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('nikto-to-hdf')) return;
  registerFingerprint(niktoFingerprint);
}
