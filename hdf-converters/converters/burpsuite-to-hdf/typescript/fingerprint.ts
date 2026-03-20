/**
 * Burp Suite format fingerprint.
 *
 * Detects Burp Suite XML files by checking for <issues> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const burpsuiteFingerprint: ConverterFingerprint = {
  id: 'burpsuite-to-hdf',
  label: 'Burp Suite',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    // BurpSuite XML has <!DOCTYPE issues [...]> before <issues> root,
    // so we check for burpVersion attribute + <issues element directly
    if (input.includes('burpVersion') && input.includes('<issues')) return 1.0;
    // Fallback: <issues> root without burpVersion (less certain)
    if (input.match(/<issues[\s>]/)) return 0.7;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('burpsuite-to-hdf')) return;
  registerFingerprint(burpsuiteFingerprint);
}
