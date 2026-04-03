/**
 * Burp Suite format fingerprint.
 *
 * Detects Burp Suite XML files by checking for <issues> root element.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';
import { extractXmlRootElement } from '../../../shared/typescript/xml-utils.js';

export const burpsuiteFingerprint: ConverterFingerprint = {
  id: 'burpsuite-to-hdf',
  label: 'Burp Suite',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'string') return 0;
    // BurpSuite XML has <!DOCTYPE issues [...]> before <issues> root.
    // extractXmlRootElement handles DOCTYPE stripping.
    const root = extractXmlRootElement(input);
    if (root !== 'issues') return 0;
    // burpVersion attribute is a strong signal
    if (input.includes('burpVersion')) return 1.0;
    return 0.7;
  },
};

export function register(): void {
  if (getFingerprint('burpsuite-to-hdf')) return;
  registerFingerprint(burpsuiteFingerprint);
}
