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
    // Extract root element: match first opening tag after XML declaration/comments
    // Handle namespace prefixes: <ns:ElementName or <ElementName
    const rootMatch = input.match(/<(?:\?[^?]*\?>[\s]*)*(?:!--[\s\S]*?-->[\s]*)*<(?:[a-zA-Z_][\w.-]*:)?([a-zA-Z_][\w.-]*)/);
    if (!rootMatch) return 0;
    const root = rootMatch[1];
    // <issues> with burpVersion attribute is a stronger signal
    if (root === 'issues') {
      if (input.includes('burpVersion')) return 1.0;
      return 0.9;
    }
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('burpsuite-to-hdf')) return;
  registerFingerprint(burpsuiteFingerprint);
}
