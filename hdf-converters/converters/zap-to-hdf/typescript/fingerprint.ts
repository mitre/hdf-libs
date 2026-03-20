/**
 * OWASP ZAP format fingerprint.
 *
 * Detects ZAP JSON output by checking for a site array with alerts.
 * ZAP outputs JSON (not XML), containing @generated/@version and site[] fields.
 * Note: ZAP can also output SARIF — the SARIF fingerprint handles that case.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const zapFingerprint: ConverterFingerprint = {
  id: 'zap-to-hdf',
  label: 'OWASP ZAP',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    // ZAP JSON has a "site" array and optionally "@generated", "@version"
    if (Array.isArray(obj.site)) {
      // Higher confidence if @version or @generated present (standard ZAP fields)
      if (typeof obj['@version'] === 'string' || typeof obj['@generated'] === 'string') return 0.95;
      return 0.85;
    }
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('zap-to-hdf')) return;
  registerFingerprint(zapFingerprint);
}
