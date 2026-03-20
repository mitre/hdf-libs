/**
 * Fortify FVDL format fingerprint.
 *
 * Detects Fortify XML files by checking for <FVDL> root element.
 * Fortify uses the FVDL (Fortify Vulnerability Description Language) format
 * with xmlns="xmlns.fortify.com/schema/fvdl" namespace.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const fortifyFingerprint: ConverterFingerprint = {
  id: 'fortify-to-hdf',
  label: 'Fortify',
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
    if (root === 'FVDL') {
      // Higher confidence with Fortify namespace
      if (input.includes('xmlns.fortify.com')) return 1.0;
      return 0.95;
    }
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('fortify-to-hdf')) return;
  registerFingerprint(fortifyFingerprint);
}
